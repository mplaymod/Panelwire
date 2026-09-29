#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8090}"
APP="/opt/wg-panel"
VENV="$APP/venv"
WEB="$APP/web"
DB="$APP/panel.db"
CREDS="/root/wg-panel-credentials.txt"
WG="/etc/wireguard/wg0.conf"

echo "=========================================="
echo " WireGuard VPS Panel"
echo " Ubuntu 22.04"
echo "=========================================="

if [ "$(id -u)" != "0" ]; then
    echo "Ejecutá este instalador como root."
    exit 1
fi

if ! command -v wg >/dev/null 2>&1; then
    echo "ERROR: WireGuard no está instalado."
    echo "Instalá WireGuard primero."
    exit 1
fi

if ! ip link show wg0 >/dev/null 2>&1; then
    echo "ERROR: wg0 no existe o no está levantado."
    exit 1
fi

echo "[1/8] Instalando dependencias..."

apt-get update

DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-venv \
    python3-dev \
    qrencode \
    iproute2 \
    wireguard \
    >/dev/null

echo "[2/8] Preparando aplicación..."

mkdir -p "$APP"
mkdir -p "$WEB"
mkdir -p "$WEB/qrs"

chmod 700 "$APP"
chmod 700 "$WEB/qrs"

echo "[3/8] Creando entorno Python..."

if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi

"$VENV/bin/pip" install --upgrade pip >/dev/null

echo "[4/8] Instalando Flask, psutil y QR..."

"$VENV/bin/pip" install \
    flask \
    psutil \
    "qrcode[pil]" \
    >/dev/null

echo "[5/8] Configurando credenciales..."

if [ -f "$CREDS" ]; then

    ADMIN_USER="$(sed -n 's/^USER=//p' "$CREDS")"
    ADMIN_PASS="$(sed -n 's/^PASS=//p' "$CREDS")"

else

    ADMIN_USER="admin"
    ADMIN_PASS="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(14))
PY
)"

    umask 077

    cat > "$CREDS" <<EOF
USER=$ADMIN_USER
PASS=$ADMIN_PASS
EOF

    chmod 600 "$CREDS"

fi

SECRET="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"

echo "[6/8] Creando panel..."

cat > "$APP/app.py" <<'PY'
import os
import sqlite3
import secrets
import subprocess
import time
import threading
import io

from functools import wraps
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template_string,
    send_file,
    abort
)

import psutil
import qrcode


APP = "/opt/wg-panel"
DB = APP + "/panel.db"
WG = "/etc/wireguard/wg0.conf"
QRDIR = APP + "/web/qrs"

USER = os.environ.get("WG_PANEL_USER", "admin")
PASS = os.environ.get("WG_PANEL_PASS", "")
SECRET = os.environ.get("WG_PANEL_SECRET", "")

app = Flask(__name__)
app.secret_key = SECRET


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def initdb():
    c = db()

    c.execute("""
        CREATE TABLE IF NOT EXISTS clients(
            public_key TEXT PRIMARY KEY,
            name TEXT,
            ip TEXT UNIQUE,
            created INTEGER,
            private_key TEXT,
            config TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS samples(
            ts INTEGER,
            public_key TEXT,
            rx INTEGER,
            tx INTEGER,
            handshake INTEGER
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS traffic(
            ts INTEGER,
            rx INTEGER,
            tx INTEGER
        )
    """)

    c.commit()
    c.close()


def wg_dump():

    try:

        out = subprocess.check_output(
            ["wg", "show", "wg0", "dump"],
            text=True,
            stderr=subprocess.DEVNULL
        )

    except Exception:
        return []

    rows = []

    lines = out.strip().splitlines()

    if len(lines) < 2:
        return rows

    for line in lines[1:]:

        p = line.split("\t")

        if len(p) < 8:
            continue

        try:

            rows.append({
                "public": p[0],
                "endpoint": p[2],
                "allowed": p[3],
                "handshake": int(p[4]),
                "rx": int(p[5]),
                "tx": int(p[6])
            })

        except Exception:
            pass

    return rows


def sample():

    rows = wg_dump()

    c = db()

    now = int(time.time())

    for r in rows:

        c.execute(
            "INSERT INTO samples VALUES(?,?,?,?,?)",
            (
                now,
                r["public"],
                r["rx"],
                r["tx"],
                r["handshake"]
            )
        )

    net = psutil.net_io_counters()

    c.execute(
        "INSERT INTO traffic VALUES(?,?,?)",
        (
            now,
            net.bytes_recv,
            net.bytes_sent
        )
    )

    # Mantener 31 días
    c.execute(
        "DELETE FROM samples WHERE ts < ?",
        (now - 31 * 86400,)
    )

    c.execute(
        "DELETE FROM traffic WHERE ts < ?",
        (now - 31 * 86400,)
    )

    c.commit()
    c.close()


def background():

    while True:

        try:
            sample()

        except Exception:
            pass

        time.sleep(60)


def auth(f):

    @wraps(f)
    def w(*a, **k):

        if not session.get("ok"):
            return redirect(url_for("login"))

        return f(*a, **k)

    return w


BASE = """
<!doctype html>

<html>

<head>

<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>WireGuard VPS Panel</title>

<style>

body{
    margin:0;
    background:#07101f;
    color:#eaf2ff;
    font-family:Arial,sans-serif;
}

nav{
    padding:18px;
    background:#101d34;
    display:flex;
    justify-content:space-between;
    align-items:center;
}

.wrap{
    max-width:1200px;
    margin:auto;
    padding:18px;
}

.grid{
    display:grid;
    grid-template-columns:
    repeat(auto-fit,minmax(180px,1fr));
    gap:12px;
}

.card{
    background:#13233d;
    border-radius:14px;
    padding:17px;
    box-shadow:0 5px 20px #0005;
}

.big{
    font-size:26px;
    font-weight:bold;
    margin-top:8px;
}

table{
    width:100%;
    border-collapse:collapse;
    background:#13233d;
    border-radius:12px;
    overflow:hidden;
}

td,th{
    padding:12px;
    border-bottom:1px solid #263a5a;
    text-align:left;
}

a,button{
    background:#087eff;
    color:white;
    border:0;
    border-radius:8px;
    padding:9px 12px;
    text-decoration:none;
    cursor:pointer;
}

.red{
    background:#d83a56;
}

.green{
    color:#55e38a;
}

.yellow{
    color:#ffd45a;
}

.muted{
    color:#9db0ca;
}

input{
    padding:11px;
    border-radius:8px;
    border:1px solid #334765;
    background:#0c1628;
    color:white;
    width:100%;
    box-sizing:border-box;
}

form{
    display:flex;
    gap:8px;
    flex-wrap:wrap;
}

form input{
    flex:1;
}

@media(max-width:700px){

table{
    font-size:12px;
}

td,th{
    padding:8px;
}

}

</style>

</head>

<body>

<nav>

<b>WireGuard VPS Panel</b>

<a href="/logout">Salir</a>

</nav>

<div class="wrap">

{{body|safe}}

</div>

</body>

</html>
"""


LOGIN = """
<!doctype html>

<html>

<head>

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>WireGuard VPS Panel</title>

<style>

body{
background:#07101f;
color:white;
font-family:Arial;
text-align:center;
padding:60px;
}

form{
max-width:350px;
margin:auto;
}

input{
display:block;
width:100%;
padding:12px;
margin:8px 0;
box-sizing:border-box;
background:#101d34;
border:1px solid #334765;
color:white;
border-radius:8px;
}

button{
padding:12px;
width:100%;
background:#087eff;
color:white;
border:0;
border-radius:8px;
}

</style>

</head>

<body>

<h2>WireGuard VPS Panel</h2>

<form method="post">

<input
name="user"
placeholder="Usuario"
autocomplete="username"
>

<input
name="pass"
type="password"
placeholder="Contraseña"
autocomplete="current-password"
>

<button>Entrar</button>

</form>

</body>

</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        user = request.form.get("user", "")
        password = request.form.get("pass", "")

        if (
            secrets.compare_digest(user, USER)
            and secrets.compare_digest(password, PASS)
        ):

            session["ok"] = True

            return redirect("/")

    return LOGIN


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


@app.route("/")
@auth
def home():

    sample()

    c = db()

    meta = {
        r["public_key"]: dict(r)
        for r in c.execute("SELECT * FROM clients")
    }

    c.close()

    clients = []

    now = int(time.time())

    for r in wg_dump():

        m = meta.get(r["public"], {})

        clients.append({
            **r,
            **m,
            "online":
                (now - r["handshake"] < 180)
                if r["handshake"]
                else False
        })

    cpu = psutil.cpu_percent(interval=.2)

    vm = psutil.virtual_memory()

    disk = psutil.disk_usage("/")

    net = psutil.net_io_counters()

    load = os.getloadavg()[0]

    body = f"""

<h2>Resumen de VPS</h2>

<div class="grid">

<div class="card">

CPU

<div class="big">
{cpu:.1f}%
</div>

</div>


<div class="card">

RAM

<div class="big">
{vm.percent:.1f}%
</div>

<span class="muted">
{vm.used/1024**3:.2f} /
{vm.total/1024**3:.2f} GB
</span>

</div>


<div class="card">

DISCO

<div class="big">
{disk.percent:.1f}%
</div>

<span class="muted">
{disk.used/1024**3:.1f} /
{disk.total/1024**3:.1f} GB
</span>

</div>


<div class="card">

Carga

<div class="big">
{load:.2f}
</div>

</div>


<div class="card">

Tráfico VPS

<div class="big">
↓ {net.bytes_recv/1024**3:.2f} GB
</div>

<span class="muted">
↑ {net.bytes_sent/1024**3:.2f} GB
</span>

</div>

</div>


<h2>Clientes WireGuard ({len(clients)})</h2>

<p>

<a href="/new">
+ Nuevo cliente
</a>

</p>

<table>

<tr>

<th>Cliente</th>
<th>IP</th>
<th>Estado</th>
<th>Handshake</th>
<th>↓ RX</th>
<th>↑ TX</th>
<th>Acciones</th>

</tr>

"""

    for x in clients:

        if x["handshake"]:

            seconds = max(
                0,
                now - x["handshake"]
            )

            if seconds < 60:
                hs = f"{seconds}s"

            elif seconds < 3600:
                hs = f"{seconds//60}m"

            else:
                hs = f"{seconds//3600}h"

        else:

            hs = "Nunca"

        status = (
            '<span class="green">● ONLINE</span>'
            if x["online"]
            else
            '<span class="muted">● OFFLINE</span>'
        )

        body += f"""

<tr>

<td>
{x.get("name") or "Sin nombre"}
</td>

<td>
{x.get("ip") or x["allowed"]}
</td>

<td>
{status}
</td>

<td>
{hs}
</td>

<td>
{x["rx"]/1024**2:.2f} MB
</td>

<td>
{x["tx"]/1024**2:.2f} MB
</td>

<td>

<a href="/qr/{x['public']}">
QR
</a>

<a href="/config/{x['public']}">
CONF
</a>

</td>

</tr>

"""

    body += """

</table>

<p class="muted">

Online = handshake en los últimos 180 segundos.

RX/TX son los contadores reales de WireGuard.

</p>

"""

    return render_template_string(
        BASE,
        body=body
    )


@app.route("/new", methods=["GET", "POST"])
@auth
def new():

    if request.method == "POST":

        name = request.form.get(
            "name",
            "Cliente"
        ).strip()[:80]

        if not name:
            name = "Cliente"

        c = db()

        used = set(
            r["ip"]
            for r in c.execute(
                "SELECT ip FROM clients"
            )
        )

        ip = None

        for n in range(2, 255):

            candidate = f"10.66.0.{n}"

            if candidate not in used:

                ip = candidate
                break

        if not ip:

            c.close()

            abort(
                400,
                "No hay IPs disponibles"
            )

        priv = subprocess.check_output(
            ["wg", "genkey"],
            text=True
        ).strip()

        pub = subprocess.check_output(
            ["wg", "pubkey"],
            input=priv,
            text=True
        ).strip()

        serverpub = subprocess.check_output(
            ["wg", "show", "wg0", "public-key"],
            text=True
        ).strip()

        # Obtener IP pública de la VPS.
        endpoint_ip = request.host.split(":")[0]

        conf = f"""[Interface]
PrivateKey = {priv}
Address = {ip}/32
DNS = 1.1.1.1

[Peer]
PublicKey = {serverpub}
Endpoint = {endpoint_ip}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

        with open(WG, "a") as f:

            f.write(
                f"""
[Peer]
# {name}
PublicKey = {pub}
AllowedIPs = {ip}/32
"""
            )

        subprocess.run(
            [
                "wg",
                "set",
                "wg0",
                "peer",
                pub,
                "allowed-ips",
                f"{ip}/32"
            ],
            check=True
        )

        c.execute(
            """
            INSERT INTO clients
            VALUES(?,?,?,?,?,?)
            """,
            (
                pub,
                name,
                ip,
                int(time.time()),
                priv,
                conf
            )
        )

        c.commit()
        c.close()

        img = qrcode.make(conf)

        img.save(
            f"{QRDIR}/{pub}.png"
        )

        return redirect("/")

    body = """

<h2>Nuevo cliente</h2>

<form method="post">

<input
name="name"
placeholder="Nombre del cliente"
required
>

<button>
Crear cliente
</button>

</form>

<p>

<a href="/">
Volver
</a>

</p>

"""

    return render_template_string(
        BASE,
        body=body
    )


@app.route("/qr/<pub>")
@auth
def qr(pub):

    c = db()

    r = c.execute(
        "SELECT * FROM clients WHERE public_key=?",
        (pub,)
    ).fetchone()

    c.close()

    if not r:
        abort(404)

    return f"""

<div style="
background:#111;
color:white;
text-align:center;
font-family:Arial;
padding:25px;
min-height:100vh;
">

<h2>
{r['name']}
</h2>

<p>
{r['ip']}
</p>

<img
style="
background:white;
padding:15px;
max-width:90%;
"
src="/qrfile/{pub}"
>

<p>

<a
style="color:white"
href="/"
>
Volver
</a>

</p>

</div>

"""


@app.route("/qrfile/<pub>")
@auth
def qrfile(pub):

    p = f"{QRDIR}/{pub}.png"

    if not os.path.exists(p):
        abort(404)

    return send_file(
        p,
        mimetype="image/png"
    )


@app.route("/config/<pub>")
@auth
def config(pub):

    c = db()

    r = c.execute(
        "SELECT * FROM clients WHERE public_key=?",
        (pub,)
    ).fetchone()

    c.close()

    if not r:
        abort(404)

    return send_file(
        io.BytesIO(
            r["config"].encode()
        ),
        as_attachment=True,
        download_name=f"{r['name']}.conf",
        mimetype="text/plain"
    )


initdb()


if __name__ == "__main__":

    threading.Thread(
        target=background,
        daemon=True
    ).start()

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                "8090"
            )
        )
    )

PY


echo "[7/8] Creando servicio systemd..."

cat > /etc/systemd/system/wg-panel.service <<EOF
[Unit]
Description=WireGuard VPS Web Panel
After=network-online.target wg-quick@wg0.service
Wants=network-online.target
Requires=wg-quick@wg0.service

[Service]
Type=simple
User=root
WorkingDirectory=$APP

Environment=PORT=$PORT
Environment=WG_PANEL_USER=$ADMIN_USER
Environment=WG_PANEL_PASS=$ADMIN_PASS
Environment=WG_PANEL_SECRET=$SECRET

ExecStart=$VENV/bin/python $APP/app.py

Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF


echo "[8/8] Iniciando panel..."

# Parar únicamente el servidor temporal que usamos para los QR.
pkill -f "python3 -m http.server 8090" 2>/dev/null || true

systemctl daemon-reload

systemctl enable wg-panel.service

systemctl restart wg-panel.service

sleep 2

if ! systemctl is-active --quiet wg-panel.service; then

    echo
    echo "ERROR: El panel no pudo arrancar."
    echo
    systemctl --no-pager --full status wg-panel.service
    echo
    journalctl -u wg-panel.service -n 50 --no-pager
    exit 1

fi


echo
echo "=========================================="
echo " PANEL INSTALADO CORRECTAMENTE"
echo "=========================================="
echo
echo "URL:"
echo "http://$(hostname -I | awk '{print $1}'):$PORT"
echo
echo "USUARIO:"
echo "$ADMIN_USER"
echo
echo "CONTRASEÑA:"
echo "$ADMIN_PASS"
echo
echo "CREDENCIALES:"
echo "$CREDS"
echo
echo "WireGuard:"
echo "Puerto 51820/UDP"
echo
echo "Panel:"
echo "Puerto $PORT/TCP"
echo
echo "=========================================="

systemctl --no-pager --full status wg-panel.service | tail -20
