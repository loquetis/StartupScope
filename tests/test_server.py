"""Server tests (box): endpoints, security rules, id-only actions, confirmations, CSV, launcher smoke test."""
import csv, io, json, os, re, subprocess, sys, tempfile, threading, time, urllib.request, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import *
from fakeplat import *
R = Results(); ok = R.ok
PORT = 18791; os.environ["STARTUPSCOPE_PORT"] = str(PORT)
store, tmp = tmpstore(); os.environ["STARTUPSCOPE_DATA"] = tmp
import server, storage
plat = demo_platform(admin=False)
server.init(plat=plat, store=store); server.on_start()
httpd = server.build_server(PORT); threading.Thread(target=httpd.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d" % PORT
def req(path, method="GET", body=None, headers=None):
    r = urllib.request.Request(URL + path, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp: return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e: return e.code, e.read(), dict(e.headers)
def jget(path): s, b, h = req(path); return s, json.loads(b)
t0 = time.time()
while (server.SC.state["scanning"] or not server.SC.state["last_scan"] or server.SC.state["to_verify"]) and time.time() - t0 < 20: time.sleep(0.1)
time.sleep(0.3)
s, page, hdr = req("/"); token = re.search(rb'name="app-token" content="([^"]+)"', page).group(1).decode()
J = {"Content-Type": "application/json", "X-App-Token": token}
def post(path, obj, headers=None): s, b, h = req(path, "POST", json.dumps(obj).encode(), headers or J); return s, json.loads(b)
def item(name, kind=None): return next(i for i in jget("/api/items")[1]["items"] if (i["name"] == name or i["display"] == name) and (kind is None or i["kind"] == kind))

ok("index page served with token injected", s == 200 and len(token) > 20 and b"__APP_TOKEN__" not in page)
ok("strict CSP", "default-src 'self'" in hdr["Content-Security-Policy"] and "script-src 'self'" in hdr["Content-Security-Policy"] and "unsafe-inline" not in hdr["Content-Security-Policy"] and "frame-ancestors 'none'" in hdr["Content-Security-Policy"])
ok("no-store + nosniff", hdr["Cache-Control"] == "no-store" and hdr["X-Content-Type-Options"] == "nosniff")
ok("no inline script/style/handlers in html", not re.search(rb"<script(?![^>]*src=)[^>]*>|style=|onclick=|onerror=|javascript:", page))
for f in ("app.js", "core.js", "styles.css", "app.css", "favicon.svg"): ok("static " + f, req("/" + f)[0] == 200)
_js = re.sub(r"/\*.*?\*/", "", open(os.path.join(ROOT, "web", "app.js")).read() + open(os.path.join(ROOT, "web", "core.js")).read(), flags=re.S)
ok("no innerHTML/eval/document.write in JS", not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function", _js))
ok("path traversal blocked", req("/..%2f..%2fserver.py")[0] == 404 and req("/../server.py")[0] == 404 and req("/%2e%2e/server.py")[0] == 404 and req("/..%5cstartup.py")[0] == 404)
ok("bad Host header rejected", req("/api/status", headers={"Host": "evil.example"})[0] == 403 and req("/", headers={"Host": "127.0.0.1:1"})[0] == 403)
ok("localhost Host accepted", req("/api/status", headers={"Host": "localhost:%d" % PORT})[0] == 200)
s, st = jget("/api/status")
ok("status fields", s == 200 and st["version"] == "1.0.0" and st["total"] == len(jget("/api/items")[1]["items"]) and st["admin"] is False and st["impact"]["ok"] and st["impact"]["boot_ms"] == 48230 and st["counts"]["service"] == 4 and st["unsigned"] >= 2 and st["data_dir"] == tmp, st)
ok("signature pass finished", not st["verifying"] and not st["scanning"])
s, its = jget("/api/items"); ok("items endpoint, no internals leaked", s == 200 and len(its["items"]) == 20 and not any(k.startswith("_") for i in its["items"] for k in i) and "_ref" not in json.dumps(its))

# security of POST routes
ok("POST without token -> 403", req("/api/toggle", "POST", b"{}", {"Content-Type": "application/json"})[0] == 403)
ok("POST with wrong token -> 403", req("/api/toggle", "POST", b"{}", {"Content-Type": "application/json", "X-App-Token": "nope"})[0] == 403)
ok("POST with non-JSON content type -> 415", req("/api/toggle", "POST", b"{}", {"Content-Type": "text/plain", "X-App-Token": token})[0] == 415)
ok("POST with non-object JSON -> 400", req("/api/toggle", "POST", b"[1]", J)[0] == 400 and req("/api/toggle", "POST", b"{bad", J)[0] == 400)
ok("POST oversize body -> 413", req("/api/toggle", "POST", b"{" + b" " * 300000 + b"}", J)[0] == 413)
ok("POST with bad Host -> 403", req("/api/toggle", "POST", b"{}", dict(J, Host="evil.example"))[0] == 403)
ok("GET on a POST route / unknown route -> 404", req("/api/toggle")[0] == 404 and req("/api/nothing")[0] == 404)
ok("toggle validation", post("/api/toggle", {})[0] == 400 and post("/api/toggle", {"id": 5, "enabled": True})[0] == 400 and post("/api/toggle", {"id": "x" * 100, "enabled": True})[0] == 400 and post("/api/toggle", {"id": "abc"})[0] == 400 and post("/api/toggle", {"id": "abc", "enabled": "yes"})[0] == 400)
ok("unknown id -> 404", post("/api/toggle", {"id": "doesnotexist", "enabled": False})[0] == 404 and post("/api/reveal", {"id": "doesnotexist"})[0] == 404)
ok("arbitrary registry path / task / command in the body is ignored (only id is used)", post("/api/toggle", {"key": "HKLM\\SOFTWARE\\x", "task": "\\evil", "command": "calc.exe", "enabled": False})[0] == 400 and plat.calls == [])

# toggling through the API
sp = item("Spotify")
s, r = post("/api/toggle", {"id": sp["id"], "enabled": False})
ok("toggle off a Run entry", s == 200 and r["ok"] and r["item"]["enabled"] is False and r["change"]["id"] == 1, r)
ok("change shows in /api/changes", jget("/api/changes")[1]["changes"][0]["display"] == "Spotify" and jget("/api/changes")[1]["backup_dir"] == store.backups)
s, r = post("/api/undo", {"change_id": 1}); time.sleep(0.5)
ok("undo restores it", r["ok"] and item("Spotify")["enabled"] is True)
ok("undo again -> 404, bad id -> 400", post("/api/undo", {"change_id": 1})[0] == 404 and post("/api/undo", {})[0] == 400 and post("/api/undo", {"change_id": "1"})[0] == 400 and post("/api/undo", {"change_id": True})[0] == 400)
s, r = post("/api/toggle", {"id": item("SecurityHealth")["id"], "enabled": False})
ok("HKLM item without admin: 200 with ok=false, needs_admin and a clear message", s == 200 and r["ok"] is False and r["needs_admin"] is True and "administrator" in r["error"], r)
s, r = post("/api/toggle", {"id": item("Spooler")["id"], "enabled": False})
ok("protected Windows service refused", r["ok"] is False and not r["needs_admin"] and "Windows" in r["error"], r)
plat._admin = True; server.SC.scan(); server.SC.verify_all()
cb = item("ContosoBackupSvc"); s, r = post("/api/toggle", {"id": cb["id"], "enabled": False})
ok("service toggle asks for confirmation first, changes nothing yet", r.get("confirm") == "service" and r["ok"] is False and not any("sc.exe" in c[0] for c in plat.calls))
s, r = post("/api/toggle", {"id": cb["id"], "enabled": False, "confirm": True})
ok("service toggle after confirm runs sc config", r["ok"] and plat.calls[-1][:3] == ["sc.exe", "config", "ContosoBackupSvc"], r)
s, r = post("/api/toggle", {"id": item("NorthwindSyncUpdate")["id"], "enabled": False})
ok("task toggle (admin)", r["ok"] and plat.calls[-1][-1] == "/disable")
plat._admin = False; server.SC.scan(); server.SC.verify_all()

# reveal
s, r = post("/api/reveal", {"id": item("Spotify")["id"]})
ok("reveal opens the item's own file by id", r["ok"] and plat.revealed == [r"C:\Users\Demo\AppData\Roaming\Spotify\Spotify.exe"], plat.revealed)
s, r = post("/api/reveal", {"id": item("CorpAgent")["id"]})
ok("reveal of a missing file explains instead of failing", s == 200 and r["ok"] is False and "not found" in r["error"])

# csv
s, raw, h = req("/api/export.csv"); rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
ok("CSV export", s == 200 and h["Content-Type"].startswith("text/csv") and "attachment" in h["Content-Disposition"] and rows[0][0] == "Name" and len(rows) == len(jget("/api/items")[1]["items"]) + 1)
plat.reg.put("HKCU", RUN_HKCU, "=cmd|' /c calc'!A1", r"C:\x\y.exe"); server.SC.scan(); s, raw, h = req("/api/export.csv")
ok("CSV injection: formula-looking names are prefixed with '", "'=cmd" in raw.decode("utf-8") and "\n=cmd" not in raw.decode("utf-8"))

# refresh + status
s, r = post("/api/refresh", {}); ok("refresh accepted", r["ok"])
t0 = time.time()
while time.time() - t0 < 10 and jget("/api/status")[1]["scanning"]: time.sleep(0.1)
ok("quit endpoint is POST-only and needs the token", req("/api/quit")[0] == 404 and req("/api/quit", "POST", b"{}", {"Content-Type": "application/json"})[0] == 403)

# ---- launcher smoke test (real entry point, own data dir; non-Windows so the list is empty)
env = dict(os.environ, STARTUPSCOPE_DATA=tempfile.mkdtemp(prefix="ssl-"), STARTUPSCOPE_PORT="18792")
p = subprocess.Popen([sys.executable, os.path.join(ROOT, "launcher.py"), "--no-window", "--port", "18792"], env=env, cwd=ROOT)
try:
    for _ in range(60):
        try: urllib.request.urlopen("http://127.0.0.1:18792/api/status", timeout=2); break
        except Exception: time.sleep(0.25)
    st2 = json.loads(urllib.request.urlopen("http://127.0.0.1:18792/api/status", timeout=5).read())
    ok("launcher: serves (empty list off Windows) and creates its data dir", st2["version"] == "1.0.0" and os.path.isfile(os.path.join(env["STARTUPSCOPE_DATA"], "startupscope.log")), st2)
    p2 = subprocess.run([sys.executable, os.path.join(ROOT, "launcher.py"), "--no-window", "--port", "18792"], env=env, cwd=ROOT, timeout=20)
    ok("launcher: second instance on busy port exits 0 (already running)", p2.returncode == 0)
    pg = urllib.request.urlopen("http://127.0.0.1:18792/", timeout=5).read(); tk = re.search(rb'name="app-token" content="([^"]+)"', pg).group(1).decode()
    urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:18792/api/quit", data=b"{}", method="POST", headers={"Content-Type": "application/json", "X-App-Token": tk}), timeout=5)
    try: p.wait(15)
    except subprocess.TimeoutExpired: pass
finally:
    if p.poll() is None: p.terminate(); p.wait(10)
ok("launcher: /api/quit ends the process cleanly", p.returncode == 0, p.returncode)
shutil.rmtree(tmp, ignore_errors=True); shutil.rmtree(env["STARTUPSCOPE_DATA"], ignore_errors=True)
R.done()
