#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8090}"
APP=/opt/wg-panel
VENV=$APP/venv
DB=$APP/panel.db
QRDIR=$APP/qrs
CREDS=/root/wg-panel-credentials.txt
WG=/etc/wireguard/wg0.conf

[[ $EUID -eq 0 ]] || { echo 'Ejecuta como root.'; exit 1; }
command -v wg >/dev/null || { echo 'ERROR: WireGuard no está instalado.'; exit 1; }
ip link show wg0 >/dev/null 2>&1 || { echo 'ERROR: wg0 no está levantado.'; exit 1; }

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-dev qrencode iproute2
mkdir -p "$APP" "$QRDIR"
chmod 700 "$APP" "$QRDIR"
python3 -m venv "$VENV" 2>/dev/null || true
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q flask psutil "qrcode[pil]"

if [[ -f "$CREDS" ]]; then
  USERNAME=$(sed -n 's/^USER=//p' "$CREDS" | head -1)
  PASSWORD=$(sed -n 's/^PASS=//p' "$CREDS" | head -1)
else
  USERNAME=admin
  PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')
  umask 077; printf 'USER=%s\nPASS=%s\n' "$USERNAME" "$PASSWORD" > "$CREDS"
fi
SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
PUBLIC_IP="${PUBLIC_IP:-$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}')}"
PUBLIC_IP="${PUBLIC_IP:-$(hostname -I | awk '{print $1}')}"

cat > "$APP/app.py" <<'PY'
import os,re,io,time,sqlite3,secrets,subprocess,threading
from functools import wraps
from flask import Flask,request,redirect,url_for,session,render_template_string,send_file,abort
import psutil,qrcode

APP='/opt/wg-panel'; DB=APP+'/panel.db'; WG='/etc/wireguard/wg0.conf'; QRDIR=APP+'/qrs'
PORT=int(os.getenv('PORT','8090')); USER=os.getenv('WG_PANEL_USER','admin'); PASS=os.getenv('WG_PANEL_PASS',''); SECRET=os.getenv('WG_PANEL_SECRET',''); PUBLIC_IP=os.getenv('WG_PUBLIC_IP','')
app=Flask(__name__); app.secret_key=SECRET; app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax')

def db():
 c=sqlite3.connect(DB,timeout=10); c.row_factory=sqlite3.Row; return c

def initdb():
 c=db(); c.execute('''CREATE TABLE IF NOT EXISTS clients(public_key TEXT PRIMARY KEY,name TEXT NOT NULL,ip TEXT,created INTEGER,private_key TEXT,config TEXT,enabled INTEGER DEFAULT 1)'''); c.execute('''CREATE TABLE IF NOT EXISTS samples(ts INTEGER,public_key TEXT,rx INTEGER,tx INTEGER,handshake INTEGER)'''); c.execute('''CREATE TABLE IF NOT EXISTS vps_samples(ts INTEGER PRIMARY KEY,rx INTEGER,tx INTEGER)'''); c.commit(); c.close()

def csrf():
 session.setdefault('csrf',secrets.token_urlsafe(24)); return session['csrf']

def check_csrf():
 if not secrets.compare_digest(request.form.get('csrf',''),session.get('csrf','')): abort(403)

def auth(f):
 @wraps(f)
 def w(*a,**k): return f(*a,**k) if session.get('ok') else redirect('/login')
 return w

def run(*args,input_text=None): return subprocess.check_output(args,text=True,input=input_text,stderr=subprocess.DEVNULL).strip()

def wg_dump():
 try: out=run('wg','show','wg0','dump')
 except: return []
 rows=[]
 for line in out.splitlines()[1:]:
  p=line.split('\t')
  if len(p)<8: continue
  try: rows.append({'public':p[0],'endpoint':p[2],'allowed':p[3],'handshake':int(p[4]),'rx':int(p[5]),'tx':int(p[6])})
  except: pass
 return rows

def ip_from_allowed(a):
 m=re.search(r'(10\.66\.0\.\d+)/32',a or ''); return m.group(1) if m else None

def conf_peers():
 if not os.path.exists(WG): return []
 text=open(WG,encoding='utf-8').read(); out=[]
 for block in re.split(r'(?=^\[Peer\]\s*$)',text,flags=re.M):
  if not re.search(r'^\[Peer\]\s*$',block,re.M): continue
  p=re.search(r'^\s*PublicKey\s*=\s*(.+?)\s*$',block,re.M); a=re.search(r'^\s*AllowedIPs\s*=\s*(.+?)\s*$',block,re.M); n=re.search(r'^\s*#\s*(.+?)\s*$',block,re.M)
  if p: out.append((p.group(1).strip(),ip_from_allowed(a.group(1) if a else ''),n.group(1).strip() if n else 'Cliente'))
 return out

def sync():
 c=db(); known={r['public_key'] for r in c.execute('SELECT public_key FROM clients')}
 for pub,ip,name in conf_peers():
  if pub not in known: c.execute('INSERT INTO clients VALUES(?,?,?,?,?,?,1)',(pub,name,ip,int(time.time()),None,None))
  else: c.execute('UPDATE clients SET ip=COALESCE(NULLIF(ip,""),?) WHERE public_key=?',(ip,pub))
 c.commit(); c.close()

def sample():
 sync(); now=int(time.time()); c=db()
 for r in wg_dump(): c.execute('INSERT INTO samples VALUES(?,?,?,?,?)',(now,r['public'],r['rx'],r['tx'],r['handshake']))
 n=psutil.net_io_counters(); c.execute('INSERT OR REPLACE INTO vps_samples VALUES(?,?,?)',(now,n.bytes_recv,n.bytes_sent))
 c.execute('DELETE FROM samples WHERE ts<?',(now-31*86400,)); c.execute('DELETE FROM vps_samples WHERE ts<?',(now-31*86400,)); c.commit(); c.close()

def sampler():
 while True:
  try: sample()
  except: pass
  time.sleep(30)

def fmt(n):
 n=float(max(0,n))
 for u in ['B','KB','MB','GB','TB']:
  if n<1024 or u=='TB': return f'{n:.2f} {u}'
  n/=1024

def age(s):
 s=max(0,int(s)); return f'{s}s' if s<60 else f'{s//60}m' if s<3600 else f'{s//3600}h' if s<86400 else f'{s//86400}d'

def usage(pub,since):
 c=db(); rows=c.execute('SELECT rx,tx FROM samples WHERE public_key=? AND ts>=? ORDER BY ts',(pub,since)).fetchall(); c.close(); rx=tx=0
 for a,b in zip(rows,rows[1:]):
  if b['rx']>=a['rx']: rx+=b['rx']-a['rx']
  if b['tx']>=a['tx']: tx+=b['tx']-a['tx']
 return rx+tx

def esc(x):
 return str(x if x is not None else '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;').replace("'",'&#39;')

def remove_conf_peer(pub):
 text=open(WG,encoding='utf-8').read(); parts=re.split(r'(?=^\[Peer\]\s*$)',text,flags=re.M); keep=[]
 for part in parts:
  m=re.search(r'^\s*PublicKey\s*=\s*(.+?)\s*$',part,re.M)
  if re.search(r'^\[Peer\]\s*$',part,re.M) and m and m.group(1).strip()==pub: continue
  keep.append(part)
 open(WG,'w',encoding='utf-8').write(''.join(keep).rstrip()+'\n')

def add_conf_peer(pub,ip,name):
 with open(WG,'a',encoding='utf-8') as f: f.write(f'\n[Peer]\n# {name}\nPublicKey = {pub}\nAllowedIPs = {ip}/32\n')

def next_ip(c):
 used={r['ip'] for r in c.execute('SELECT ip FROM clients') if r['ip']}
 for r in wg_dump():
  x=ip_from_allowed(r['allowed'])
  if x: used.add(x)
 for i in range(2,255):
  x=f'10.66.0.{i}'
  if x not in used:return x
 return None

BASE='''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="30"><title>WireGuard VPS</title><style>*{box-sizing:border-box}body{margin:0;background:#07101f;color:#eaf2ff;font-family:Arial}nav{padding:15px 18px;background:#101d34;display:flex;justify-content:space-between;position:sticky;top:0;z-index:2}.wrap{max-width:1250px;margin:auto;padding:16px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px}.card{background:#13233d;border-radius:15px;padding:16px;box-shadow:0 5px 18px #0005}.big{font-size:25px;font-weight:bold;margin-top:7px}.muted{color:#9db0ca}.green{color:#55e38a}.redtxt{color:#ff7189}.btn{display:inline-block;background:#087eff;color:#fff;border:0;border-radius:9px;padding:9px 12px;text-decoration:none;cursor:pointer;margin:2px}.gray{background:#334765}.red{background:#d83a56}table{width:100%;border-collapse:collapse;background:#13233d;border-radius:14px;overflow:hidden}th,td{padding:10px;border-bottom:1px solid #263a5a;text-align:left;vertical-align:middle}.actions{display:flex;flex-wrap:wrap;gap:3px}.formbox{max-width:520px;background:#13233d;padding:18px;border-radius:15px}input{width:100%;padding:11px;border-radius:9px;border:1px solid #334765;background:#0c1628;color:#fff}@media(max-width:700px){table{font-size:12px}th,td{padding:7px}} </style></head><body><nav><b>WireGuard VPS Panel</b><a class="btn gray" href="/logout">Salir</a></nav><div class="wrap">{{body|safe}}</div></body></html>'''
LOGIN='''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{background:#07101f;color:#fff;font-family:Arial;text-align:center;padding:55px 18px}.box{max-width:360px;margin:auto;background:#13233d;padding:25px;border-radius:16px}input,button{width:100%;padding:12px;margin:7px 0;border-radius:9px}input{background:#0c1628;border:1px solid #334765;color:#fff}button{background:#087eff;border:0;color:white}</style></head><body><div class="box"><h2>WireGuard VPS</h2><form method="post"><input name="user" placeholder="Usuario"><input name="pass" type="password" placeholder="Contraseña"><button>Entrar</button></form></div></body></html>'''

@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST' and secrets.compare_digest(request.form.get('user',''),USER) and secrets.compare_digest(request.form.get('pass',''),PASS): session.clear(); session['ok']=True; session['csrf']=secrets.token_urlsafe(24); return redirect('/')
 return LOGIN
@app.route('/logout')
def logout(): session.clear(); return redirect('/login')

@app.route('/')
@auth
def home():
 try: sample()
 except: pass
 c=db(); meta={r['public_key']:dict(r) for r in c.execute('SELECT * FROM clients')}; c.close(); now=int(time.time()); rows=wg_dump(); clients=[]
 for r in rows:
  m=meta.get(r['public'],{}); ip=ip_from_allowed(r['allowed']) or m.get('ip') or '-'; online=bool(r['handshake'] and now-r['handshake']<180); clients.append({**r,**m,'ip':ip,'online':online,'hs':'Nunca' if not r['handshake'] else age(now-r['handshake'])})
 cpu=psutil.cpu_percent(.2); vm=psutil.virtual_memory(); disk=psutil.disk_usage('/'); net=psutil.net_io_counters(); load=os.getloadavg()[0]; on=sum(x['online'] for x in clients); day=int(time.time())//86400*86400
 body=f'<h2>Resumen de VPS</h2><div class="grid"><div class="card">CPU<div class="big">{cpu:.1f}%</div></div><div class="card">RAM<div class="big">{vm.percent:.1f}%</div><span class="muted">{vm.used/1024**3:.2f}/{vm.total/1024**3:.2f} GB</span></div><div class="card">Disco<div class="big">{disk.percent:.1f}%</div><span class="muted">{disk.used/1024**3:.1f}/{disk.total/1024**3:.1f} GB</span></div><div class="card">Carga<div class="big">{load:.2f}</div><span class="muted">{os.cpu_count() or 1} CPU</span></div><div class="card">Tráfico VPS<div class="big">↓ {fmt(net.bytes_recv)}</div><span class="muted">↑ {fmt(net.bytes_sent)}</span></div><div class="card">Clientes<div class="big">{on}/{len(clients)}</div><span class="muted">online</span></div></div><h2>Clientes WireGuard</h2><p><a class="btn" href="/new">+ Nuevo cliente</a> <a class="btn gray" href="/sync">Sincronizar</a></p><table><tr><th>Cliente</th><th>IP</th><th>Estado</th><th>Handshake</th><th>↓ RX</th><th>↑ TX</th><th>Uso hoy</th><th>Acciones</th></tr>'
 for x in clients:
  status='<span class="green">● ONLINE</span>' if x['online'] else '<span class="muted">● OFFLINE</span>'; use=usage(x['public'],day); enabled=int(x.get('enabled',1)); toggle='Bloquear' if enabled else 'Activar'; togglecls='gray' if enabled else 'green'; body+=f'<tr><td><b>{esc(x.get("name") or "Cliente")}</b><br><span class="muted">{x["public"][:12]}...</span></td><td>{x["ip"]}</td><td>{status}</td><td>{x["hs"]}</td><td>{fmt(x["rx"])}</td><td>{fmt(x["tx"])}</td><td>{fmt(use)}</td><td><div class="actions"><a class="btn" href="/qr/{x["public"]}">QR</a><a class="btn gray" href="/config/{x["public"]}">CONF</a><a class="btn gray" href="/edit/{x["public"]}">Editar</a><a class="btn {togglecls}" href="/toggle/{x["public"]}?csrf={csrf()}">{toggle}</a><a class="btn red" href="/delete/{x["public"]}?csrf={csrf()}" onclick="return confirm(\'¿Eliminar este cliente?\')">Eliminar</a></div></td></tr>'
 body+='</table><p class="muted">Actualiza cada 30 segundos. Online = handshake en los últimos 180 s. El uso diario empieza a acumularse desde que el panel toma muestras.</p><div class="card"><b>IP pública:</b> '+esc(PUBLIC_IP)+' &nbsp; <b>WireGuard:</b> UDP 51820 &nbsp; <b>Panel:</b> TCP '+str(PORT)+'</div>'
 return render_template_string(BASE,body=body)

@app.route('/sync')
@auth
def sync_route(): sync(); return redirect('/')

@app.route('/new',methods=['GET','POST'])
@auth
def new():
 if request.method=='POST':
  check_csrf(); name=request.form.get('name','').strip()[:80] or 'Cliente'; c=db(); ip=next_ip(c)
  if not ip: abort(400,'No quedan IPs disponibles.')
  priv=run('wg','genkey'); pub=run('wg','pubkey',input_text=priv); serverpub=run('wg','show','wg0','public-key'); conf=f'[Interface]\nPrivateKey = {priv}\nAddress = {ip}/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = {serverpub}\nEndpoint = {PUBLIC_IP}:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n'
  subprocess.run(['cp','-a',WG,WG+'.bak-panel'],check=False); add_conf_peer(pub,ip,name); run('wg','set','wg0','peer',pub,'allowed-ips',f'{ip}/32'); c.execute('INSERT INTO clients VALUES(?,?,?,?,?,?,1)',(pub,name,ip,int(time.time()),priv,conf)); c.commit(); c.close(); qrcode.make(conf).save(f'{QRDIR}/{pub}.png'); return redirect('/')
 return render_template_string(BASE,body=f'<h2>Nuevo cliente</h2><div class="formbox"><form method="post"><input type="hidden" name="csrf" value="{csrf()}"><input name="name" placeholder="Ej: TV Box Juan" required><br><br><button class="btn">Crear cliente</button></form></div><p><a class="btn gray" href="/">Volver</a></p>')

@app.route('/edit/<pub>',methods=['GET','POST'])
@auth
def edit(pub):
 c=db(); r=c.execute('SELECT * FROM clients WHERE public_key=?',(pub,)).fetchone(); c.close()
 if not r: abort(404)
 if request.method=='POST':
  check_csrf(); name=request.form.get('name','').strip()[:80] or 'Cliente'; c=db(); c.execute('UPDATE clients SET name=? WHERE public_key=?',(name,pub)); c.commit(); c.close(); return redirect('/')
 return render_template_string(BASE,body=f'<h2>Renombrar cliente</h2><div class="formbox"><form method="post"><input type="hidden" name="csrf" value="{csrf()}"><input name="name" value="{esc(r["name"])}" required><br><br><button class="btn">Guardar</button></form></div>')

@app.route('/toggle/<pub>')
@auth
def toggle(pub):
 if not secrets.compare_digest(request.args.get('csrf',''),session.get('csrf','')): abort(403)
 c=db(); r=c.execute('SELECT * FROM clients WHERE public_key=?',(pub,)).fetchone(); c.close()
 if not r: abort(404)
 if int(r['enabled'] or 0):
  try: run('wg','set','wg0','peer',pub,'remove')
  except: pass
  c=db(); c.execute('UPDATE clients SET enabled=0 WHERE public_key=?',(pub,)); c.commit(); c.close()
 else:
  if not r['ip']: abort(400,'Cliente sin IP.')
  run('wg','set','wg0','peer',pub,'allowed-ips',f'{r["ip"]}/32'); c=db(); c.execute('UPDATE clients SET enabled=1 WHERE public_key=?',(pub,)); c.commit(); c.close()
 return redirect('/')

@app.route('/delete/<pub>')
@auth
def delete(pub):
 if not secrets.compare_digest(request.args.get('csrf',''),session.get('csrf','')): abort(403)
 c=db(); r=c.execute('SELECT * FROM clients WHERE public_key=?',(pub,)).fetchone(); c.close()
 if not r: abort(404)
 try: run('wg','set','wg0','peer',pub,'remove')
 except: pass
 subprocess.run(['cp','-a',WG,WG+'.bak-panel'],check=False); remove_conf_peer(pub)
 try: os.remove(f'{QRDIR}/{pub}.png')
 except FileNotFoundError: pass
 c=db(); c.execute('DELETE FROM samples WHERE public_key=?',(pub,)); c.execute('DELETE FROM clients WHERE public_key=?',(pub,)); c.commit(); c.close(); return redirect('/')

@app.route('/qr/<pub>')
@auth
def qr(pub):
 c=db(); r=c.execute('SELECT * FROM clients WHERE public_key=?',(pub,)).fetchone(); c.close()
 if not r: abort(404)
 if not r['config']: return render_template_string(BASE,body=f'<h2>{esc(r["name"])}</h2><div class="card">Este peer ya existía en wg0.conf y el panel no conoce su clave privada. No se puede generar QR por seguridad.</div><p><a class="btn gray" href="/">Volver</a></p>')
 return render_template_string(BASE,body=f'<h2>{esc(r["name"])}</h2><p class="muted">{esc(r["ip"])}</p><div class="card" style="text-align:center"><img style="background:#fff;padding:14px;max-width:92%" src="/qrfile/{pub}"></div><p><a class="btn gray" href="/">Volver</a></p>')

@app.route('/qrfile/<pub>')
@auth
def qrfile(pub):
 p=f'{QRDIR}/{pub}.png'
 if not os.path.exists(p): abort(404)
 return send_file(p,mimetype='image/png')

@app.route('/config/<pub>')
@auth
def config(pub):
 c=db(); r=c.execute('SELECT * FROM clients WHERE public_key=?',(pub,)).fetchone(); c.close()
 if not r or not r['config']: abort(404,'Este cliente fue importado desde wg0.conf y no tiene clave privada almacenada por el panel.')
 name=re.sub(r'[^A-Za-z0-9_.-]+','_',r['name']) or 'cliente'; return send_file(io.BytesIO(r['config'].encode()),as_attachment=True,download_name=f'{name}.conf',mimetype='text/plain')

@app.route('/api/stats')
@auth
def api_stats():
 c=db(); rows=c.execute('SELECT ts,rx,tx FROM vps_samples WHERE ts>=? ORDER BY ts',(int(time.time())-3600,)).fetchall(); c.close(); return {'points':[dict(r) for r in rows],'cpu':psutil.cpu_percent(.1),'ram':psutil.virtual_memory().percent,'disk':psutil.disk_usage('/').percent,'load':os.getloadavg()[0]}

initdb(); sync()
if __name__=='__main__': threading.Thread(target=sampler,daemon=True).start(); app.run(host='0.0.0.0',port=PORT)
PY

cat > /etc/systemd/system/wg-panel.service <<EOF
[Unit]
Description=WireGuard VPS Admin Panel
After=network-online.target wg-quick@wg0.service
Wants=network-online.target
Requires=wg-quick@wg0.service

[Service]
Type=simple
User=root
WorkingDirectory=$APP
Environment=PORT=$PORT
Environment=WG_PANEL_USER=$USERNAME
Environment=WG_PANEL_PASS=$PASSWORD
Environment=WG_PANEL_SECRET=$SECRET
Environment=WG_PUBLIC_IP=$PUBLIC_IP
ExecStart=$VENV/bin/python $APP/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
