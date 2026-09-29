#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8090}"
APP="/opt/wg-panel"
WEB="$APP/web"
DB="$APP/panel.db"
CREDS="/root/wg-panel-credentials.txt"

echo "== WireGuard VPS Panel =="
echo "Ubuntu 22.04 x86_64 detectado."

if ! command -v wg >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip qrencode iproute2

mkdir -p "$WEB/qrs" "$APP"
chmod 700 "$APP" "$WEB/qrs"

python3 -m pip install --break-system-packages flask psutil qrcode[pil] >/dev/null

if ! ip link show wg0 >/dev/null 2>&1; then
  echo "ERROR: wg0 no existe. Levanta WireGuard primero."
  exit 1
fi

if [ -f "$CREDS" ]; then
  ADMIN_USER="$(sed -n 's/^USER=//p' "$CREDS")"
  ADMIN_PASS="$(sed -n 's/^PASS=//p' "$CREDS")"
else
  ADMIN_USER="admin"
  ADMIN_PASS="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(12))
PY
)"
  umask 077
  cat > "$CREDS" <<EOF
USER=$ADMIN_USER
PASS=$ADMIN_PASS
EOF
  chmod 600 "$CREDS"
fi

cat > "$APP/app.py" <<'PY'
import os, re, json, sqlite3, secrets, subprocess, time
from datetime import datetime
from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template_string, send_file, abort
import psutil
import qrcode

APP="/opt/wg-panel"
DB=APP+"/panel.db"
WG="/etc/wireguard/wg0.conf"
QRDIR=APP+"/web/qrs"
USER=os.environ.get("WG_PANEL_USER","admin")
PASS=os.environ["WG_PANEL_PASS"]
SECRET=os.environ["WG_PANEL_SECRET"]

app=Flask(__name__)
app.secret_key=SECRET

def db():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    return c

def initdb():
    c=db()
    c.execute("""CREATE TABLE IF NOT EXISTS clients(
      public_key TEXT PRIMARY KEY, name TEXT, ip TEXT UNIQUE,
      created INTEGER, private_key TEXT, config TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS samples(
      ts INTEGER, public_key TEXT, rx INTEGER, tx INTEGER,
      handshake INTEGER)""")
    c.commit(); c.close()

def wg_dump():
    try:
        out=subprocess.check_output(["wg","show","wg0","dump"],text=True,stderr=subprocess.DEVNULL)
    except Exception:
        return []
    rows=[]
    lines=out.strip().splitlines()
    for line in lines[1:]:
        p=line.split("\t")
        if len(p)<8: continue
        try:
            rows.append({
              "public":p[0],"endpoint":p[2],"allowed":p[3],
              "handshake":int(p[4]),"rx":int(p[5]),"tx":int(p[6])
            })
        except Exception: pass
    return rows

def sample():
    rows=wg_dump()
    c=db()
    now=int(time.time())
    for r in rows:
        c.execute("INSERT INTO samples VALUES(?,?,?,?,?)",
                  (now,r["public"],r["rx"],r["tx"],r["handshake"]))
    c.execute("DELETE FROM samples WHERE ts < ?",(now-31*86400,))
    c.commit(); c.close()

def background():
    while True:
        try: sample()
        except Exception: pass
        time.sleep(60)

def auth(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a,**k)
    return w

BASE="""
<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1">
<title>WireGuard VPS Panel</title>
<style>
body{margin:0;background:#0b1220;color:#eaf2ff;font-family:Arial}
nav{padding:18px;background:#111c31;display:flex;justify-content:space-between}
.wrap{max-width:1100px;margin:auto;padding:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.card{background:#142039;border-radius:14px;padding:16px;box-shadow:0 5px 20px #0004}
.big{font-size:25px;font-weight:bold}
table{width:100%;border-collapse:collapse;background:#142039;border-radius:12px;overflow:hidden}
td,th{padding:12px;border-bottom:1px solid #263653;text-align:left}
a,button{background:#087eff;color:white;border:0;border-radius:8px;padding:9px 12px;text-decoration:none;cursor:pointer}
.red{background:#d83a56}.green{color:#55e38a}.muted{color:#9db0ca}
input{padding:11px;border-radius:8px;border:1px solid #334765;background:#0c1628;color:white;width:100%;box-sizing:border-box}
form{display:flex;gap:8px;flex-wrap:wrap}form input{flex:1}
</style></head><body>
<nav><b>WireGuard VPS Panel</b><a href="/logout">Salir</a></nav>
<div class=wrap>{{body|safe}}</div></body></html>
"""

LOGIN="""<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{background:#0b1220;color:white;font-family:Arial;text-align:center;padding:60px}form{max-width:350px;margin:auto}input{display:block;width:100%;padding:12px;margin:8px 0;box-sizing:border-box}button{padding:12px;width:100%}</style>
<h2>WireGuard VPS Panel</h2><form method=post><input name=user placeholder=Usuario><input name=pass type=password placeholder=Contraseña><button>Entrar</button></form>
"""

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST" and secrets.compare_digest(request.form.get("user",""),USER) and secrets.compare_digest(request.form.get("pass",""),PASS):
        session["ok"]=True; return redirect("/")
    return LOGIN

@app.route("/logout")
def logout(): session.clear(); return redirect("/login")

@app.route("/")
@auth
def home():
    sample()
    clients=[]
    c=db()
    meta={r["public_key"]:dict(r) for r in c.execute("select * from clients")}
    for r in wg_dump():
        m=meta.get(r["public"],{})
        clients.append({**r,**m,"online": (int(time.time())-r["handshake"]<180) if r["handshake"] else False})
    cpu=psutil.cpu_percent(interval=.2); vm=psutil.virtual_memory(); disk=psutil.disk_usage("/")
    net=psutil.net_io_counters()
    body=f"""
    <h2>Resumen de VPS</h2><div class=grid>
    <div class=card>CPU<div class=big>{cpu:.1f}%</div></div>
    <div class=card>RAM<div class=big>{vm.percent:.1f}%</div><span class=muted>{vm.used/1024**3:.2f} / {vm.total/1024**3:.2f} GB</span></div>
    <div class=card>Disco<div class=big>{disk.percent:.1f}%</div><span class=muted>{disk.used/1024**3:.1f} / {disk.total/1024**3:.1f} GB</span></div>
    <div class=card>Tráfico eth0<div class=big>↓ {net.bytes_recv/1024**3:.2f} GB</div><span class=muted>↑ {net.bytes_sent/1024**3:.2f} GB</span></div>
    </div>
    <h2>Clientes WireGuard ({len(clients)})</h2>
    <p><a href="/new">+ Nuevo cliente</a></p>
    <table><tr><th>Cliente</th><th>IP</th><th>Estado</th><th>Handshake</th><th>↓ RX</th><th>↑ TX</th><th>Acciones</th></tr>"""
    for x in clients:
        hs="Nunca"
        if x["handshake"]:
            hs=str(max(0,int(time.time())-x["handshake"]))+" s"
        body+=f"""<tr><td>{x.get("name") or "Sin nombre"}</td><td>{x.get("ip") or x["allowed"]}</td>
        <td class="{'green' if x['online'] else 'muted'}">{'● ONLINE' if x['online'] else '● OFFLINE'}</td>
        <td>{hs}</td><td>{x['rx']/1024**2:.2f} MB</td><td>{x['tx']/1024**2:.2f} MB</td>
        <td><a href="/qr/{x['public']}">QR</a> <a href="/config/{x['public']}">CONF</a></td></tr>"""
    body+="</table><p class=muted>Online = handshake en los últimos 180 segundos. RX/TX son contadores de WireGuard.</p>"
    return render_template_string(BASE,body=body)

@app.route("/new",methods=["GET","POST"])
@auth
def new():
    if request.method=="POST":
        name=request.form.get("name","Cliente").strip()[:80] or "Cliente"
        used=set()
        c=db()
        for r in c.execute("select ip from clients"): used.add(r["ip"])
        ip=None
        for n in range(2,255):
            cand=f"10.66.0.{n}"
            if cand not in used: ip=cand; break
        if not ip: abort(400,"Sin IPs disponibles")
        priv=subprocess.check_output(["wg","genkey"],text=True).strip()
        pub=subprocess.check_output(["wg","pubkey"],input=priv,text=True).strip()
        serverpub=subprocess.check_output(["wg","show","wg0","public-key"],text=True).strip()
        conf=f"""[Interface]\nPrivateKey = {priv}\nAddress = {ip}/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = {serverpub}\nEndpoint = {request.host.split(':')[0]}:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"""
        with open(WG,"a") as f:
            f.write(f"\n[Peer]\n# {name}\nPublicKey = {pub}\nAllowedIPs = {ip}/32\n")
        subprocess.run(["wg","set","wg0","peer",pub,"allowed-ips",f"{ip}/32"],check=True)
        c.execute("insert into clients values(?,?,?,?,?,?)",(pub,name,ip,int(time.time()),priv,conf))
        c.commit(); c.close()
        img=qrcode.make(conf); img.save(f"{QRDIR}/{pub}.png")
        return redirect("/")
    body="""<h2>Nuevo cliente</h2><form method=post><input name=name placeholder="Nombre del cliente" required><button>Crear</button></form><p><a href="/">Volver</a></p>"""
    return render_template_string(BASE,body=body)

@app.route("/qr/<pub>")
@auth
def qr(pub):
    c=db(); r=c.execute("select * from clients where public_key=?",(pub,)).fetchone(); c.close()
    if not r: abort(404)
    return f"""<div style='background:#111;color:white;text-align:center;font-family:Arial;padding:25px'><h2>{r['name']}</h2><p>{r['ip']}</p><img style='background:white;padding:15px;max-width:90%' src='/qrfile/{pub}'><p><a style='color:white' href='/'>Volver</a></p></div>"""

@app.route("/qrfile/<pub>")
@auth
def qrfile(pub):
    p=f"{QRDIR}/{pub}.png"
    if not os.path.exists(p): abort(404)
    return send_file(p,mimetype="image/png")

@app.route("/config/<pub>")
@auth
def config(pub):
    c=db(); r=c.execute("select * from clients where public_key=?",(pub,)).fetchone(); c.close()
    if not r: abort(404)
    return send_file(__import__("io").BytesIO(r["config"].encode()),as_attachment=True,download_name=f"{r['name']}.conf",mimetype="text/plain")

initdb()

if __name__=="__main__":
    import threading
    threading.Thread(target=background,daemon=True).start()
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT","8090")))
PY

SECRET="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"

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
ExecStart=/usr/bin/python3 $APP/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Stop the temporary QR web server if it exists
pkill -f "python3 -m http.server 8090" 2>/dev/null || true

systemctl daemon-reload
systemctl enable --now wg-panel.service

echo
echo "=========================================="
echo " PANEL INSTALADO"
echo " URL: http://$(hostname -I | awk '{print $1}'):$PORT"
echo " USUARIO: $ADMIN_USER"
echo " CONTRASEÑA: $ADMIN_PASS"
echo "=========================================="
echo "Credenciales guardadas en: $CREDS"
systemctl --no-pager --full status wg-panel.service | tail -20
