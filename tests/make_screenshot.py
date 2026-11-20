"""Make screenshot.png: real server + fake demo Windows (made-up vendors), headless Chrome 1280x820.
Run: python tests/make_screenshot.py"""
import os, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import *
from fakeplat import *
from playwright.sync_api import sync_playwright
PORT = 18795; os.environ["STARTUPSCOPE_PORT"] = str(PORT)
store, tmp = tmpstore(); os.environ["STARTUPSCOPE_DATA"] = tmp
plat = demo_platform(admin=False)
import server
server.init(plat=plat, store=store); server.on_start()
httpd = server.build_server(PORT); threading.Thread(target=httpd.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d/" % PORT
t0 = time.time()
while (server.SC.state["scanning"] or not server.SC.state["last_scan"] or server.SC.state["to_verify"]) and time.time() - t0 < 20: time.sleep(0.1)
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    pg = b.new_context(viewport={"width": 1280, "height": 820}).new_page()
    pg.goto(URL); pg.wait_for_selector("#rows tr"); pg.wait_for_timeout(800)
    pg.mouse.move(1275, 815)
    out = os.path.join(ROOT, "screenshot.png"); pg.screenshot(path=out); print("saved", out)
    b.close()
import shutil; shutil.rmtree(tmp, ignore_errors=True)
