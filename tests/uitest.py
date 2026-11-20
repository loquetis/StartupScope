"""UI test on the box: headless Chrome against the real server with a fake Windows (open/toggle recorded).
Run: python tests/uitest.py"""
import json, os, re, sys, threading, time, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import *
from fakeplat import *
from playwright.sync_api import sync_playwright
R = Results(); ok = R.ok
PORT = 18793; os.environ["STARTUPSCOPE_PORT"] = str(PORT)
store, tmp = tmpstore(); os.environ["STARTUPSCOPE_DATA"] = tmp
plat = demo_platform(admin=False)
HOSTILE = '<img src=x onerror=window.__pwn=1>'
plat.reg.put("HKCU", RUN_HKCU, HOSTILE, r'C:\Users\Demo\AppData\Local\Temp\updater_helper.exe "<b>x</b>"')
import server
server.init(plat=plat, store=store); server.on_start()
httpd = server.build_server(PORT); threading.Thread(target=httpd.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d/" % PORT
t0 = time.time()
while (server.SC.state["scanning"] or not server.SC.state["last_scan"] or server.SC.state["to_verify"]) and time.time() - t0 < 20: time.sleep(0.1)
errors = []
def rows(pg): return pg.eval_on_selector_all("#rows tr", "els => els.map(e => e.querySelector('.nm').textContent)")
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    ctx = b.new_context(viewport={"width": 1320, "height": 860}, permissions=["clipboard-read", "clipboard-write"])
    pg = ctx.new_page(); pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None); pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(URL); pg.wait_for_selector("#rows tr"); pg.wait_for_timeout(600)
    ok("title", pg.title() == "StartupScope")
    names = rows(pg)
    ok("Windows components hidden by default (Spooler, Windows Update, CEIP task)", "Print Spooler" not in names and "Windows Update" not in names and "Consolidator" not in names and "Spotify" in names, names)
    ok("cards show totals + last boot time 48.2 s", "48.2 s" in pg.inner_text("#cards") and "startup items" in pg.inner_text("#cards").lower(), pg.inner_text("#cards"))
    ok("not-admin notice shown", "without administrator" in pg.inner_text("#banners"))
    ok("sorted by boot impact: OneDrive (High) first", names[0] == "OneDrive", names[:3])
    ok("impact text: High/Medium/n/a", "High · 4.1 s" in pg.inner_text("#rows") and "Medium" in pg.inner_text("#rows") and "n/a" in pg.inner_text("#rows"))
    ok("signature badges + publishers", pg.locator(".badge.ok").count() >= 8 and pg.locator(".badge.warn", has_text="Unsigned").count() >= 1 and pg.locator(".badge.danger", has_text="Bad signature").count() == 1 and "Spotify AB" in pg.inner_text("#rows"))
    ok("hostile name rendered as text, no injected element", pg.locator(".nm", has_text=HOSTILE).count() == 1 and pg.evaluate("document.querySelectorAll('img[src=x]').length") == 0 and pg.evaluate("window.__pwn") is None)
    ok("disabled row is struck through + switch off", pg.locator("tr.off .nm", has_text="Steam").count() == 1 and pg.locator("tr.off", has_text="Steam").locator(".switch").get_attribute("aria-checked") == "false")
    ok("locked items show Admin badge with reason, no switch", pg.locator("tr", has_text="SecurityHealth").locator(".lock").inner_text() == "Admin" and "administrator" in pg.locator("tr", has_text="SecurityHealth").locator(".lock").get_attribute("title") and pg.locator("tr", has_text="SecurityHealth").locator(".switch").count() == 0)
    # filter / sort
    pg.fill("#q", "dropbox"); pg.wait_for_timeout(200); ok("text filter", rows(pg) == ["Dropbox"], rows(pg))
    pg.fill("#q", "spotify ab"); pg.wait_for_timeout(200); ok("filter matches publisher", rows(pg) == ["Spotify"])
    pg.fill("#q", ""); pg.select_option("#f-kind", "task"); pg.wait_for_timeout(200); ok("kind filter: tasks", set(rows(pg)) == {"NorthwindSyncUpdate", "ContosoBackupStartup", "Legacy Cleaner"}, rows(pg))
    pg.select_option("#f-kind", "all"); pg.check("#f-off"); pg.wait_for_timeout(200); ok("only disabled", set(rows(pg)) == {"Steam", "Legacy Cleaner"}, rows(pg))
    pg.uncheck("#f-off"); pg.uncheck("#f-win"); pg.wait_for_timeout(200); ok("show Windows components", "Print Spooler" in rows(pg) and "Windows Update" in rows(pg) and "Consolidator" in rows(pg))
    ok("protected rows show 'Windows' badge", pg.locator("tr", has_text="Print Spooler").locator(".lock").inner_text() == "Windows")
    pg.check("#f-win"); pg.select_option("#f-sort", "name"); pg.wait_for_timeout(200); n2 = rows(pg); ok("sort by name", n2 == sorted(n2, key=str.lower), n2)
    pg.select_option("#f-sort", "impact")
    # detail
    pg.locator("tr", has_text="Dropbox").first.click(); pg.wait_for_timeout(200)
    d = pg.inner_text("#detail"); ok("detail panel: location, command, file, publisher, trigger info", "Startup folder" in d and "/systemstartup" in d and "Dropbox, Inc." in d and "Medium" in d, d)
    with ctx.expect_page() if False else open(os.devnull) as _: pass
    pg.click("#detail >> text=Show file in folder"); pg.wait_for_timeout(300); ok("reveal goes through the server by id", plat.revealed and plat.revealed[-1].endswith("Dropbox.exe"), plat.revealed)
    pg.click("#detail >> text=Copy command"); pg.wait_for_timeout(300); ok("copy command to clipboard", "Dropbox.exe" in pg.evaluate("navigator.clipboard.readText()"))
    pg.locator("tr", has_text="Dropbox").first.click(); ok("click again closes the detail", pg.locator("#detail").is_hidden())
    # toggle
    sw = pg.locator("tr", has_text="Spotify").locator(".switch"); ok("switch starts on", sw.get_attribute("aria-checked") == "true")
    sw.click(); pg.wait_for_timeout(700)
    ok("toggle off: row struck through, toast, server wrote StartupApproved", pg.locator("tr.off", has_text="Spotify").count() == 1 and "no longer start" in pg.inner_text("#toast") and plat.reg.get("HKCU", AP + r"\Run", "Spotify")[0][0] == 3)
    ok("changes counter in the sidebar", pg.inner_text("#n-changes") == "1")
    pg.click('[data-view="changes"]'); pg.wait_for_timeout(400)
    ok("changes view lists it with Undo and the backup folder", "Spotify" in pg.inner_text("#chg-rows") and "Disabled" in pg.inner_text("#chg-rows") and store.backups in pg.inner_text("#backup-dir"))
    pg.click("#chg-rows >> text=Undo"); pg.wait_for_timeout(800)
    ok("undo restores the original value", plat.reg.get("HKCU", AP + r"\Run", "Spotify")[0] == b"\x02" + b"\0" * 11 and "(undone)" in pg.inner_text("#chg-rows") and pg.inner_text("#n-changes") == "")
    pg.click('[data-view="items"]'); pg.wait_for_timeout(400); ok("row is back on", pg.locator("tr", has_text="Spotify").locator(".switch").get_attribute("aria-checked") == "true")
    # locked toggle: nothing to click; confirm with an admin session for the service dialog
    plat._admin = True; server.SC.scan(); server.SC.verify_all(); pg.click("#btn-refresh"); pg.wait_for_timeout(1500)
    ok("admin session: notice gone, locked items now have switches", "without administrator" not in pg.inner_text("#banners") and pg.locator("tr", has_text="SecurityHealth").locator(".switch").count() == 1)
    pg.locator("tr", has_text="Contoso Backup Service").locator(".switch").click(); pg.wait_for_selector(".modal")
    ok("service disable asks for confirmation (Manual, undo noted)", "Disable Contoso Backup Service?" in pg.inner_text(".modal h2") and "Manual" in pg.inner_text(".modal"))
    pg.click(".modal >> text=Cancel"); pg.wait_for_timeout(300)
    ok("cancel changes nothing", not any(c[0] == "sc.exe" for c in plat.calls) and pg.locator(".modal").count() == 0)
    pg.locator("tr", has_text="Contoso Backup Service").locator(".switch").click(); pg.wait_for_selector(".modal"); pg.click(".modal button.danger"); pg.wait_for_timeout(800)
    ok("confirmed: sc config ran, row struck through", any(c[:3] == ["sc.exe", "config", "ContosoBackupSvc"] for c in plat.calls) and pg.locator("tr.off", has_text="Contoso Backup Service").count() == 1)
    plat.rc["schtasks.exe"] = (1, "ERROR: Access is denied.")
    pg.locator("tr", has_text="NorthwindSyncUpdate").locator(".switch").click(); pg.wait_for_timeout(600)
    ok("denied change shows a clear error toast and the row stays on", "administrator" in pg.inner_text("#toast") and pg.locator("tr.off", has_text="NorthwindSyncUpdate").count() == 0)
    plat.rc.clear()
    # about, themes, narrow
    pg.click('[data-view="about"]'); ok("about page explains the method and boot impact", "StartupApproved" in pg.inner_text("#v-about") and "Windows only logs" in pg.inner_text("#about-impact"), pg.inner_text("#about-impact"))
    pg.select_option("#theme", "light"); ok("theme switch", pg.evaluate("document.documentElement.dataset.theme") == "light"); pg.select_option("#theme", "dark")
    pg.click('[data-view="items"]'); pg.set_viewport_size({"width": 720, "height": 800}); pg.wait_for_timeout(300)
    ok("narrow window still usable", pg.locator("#rows tr").count() > 5 and pg.locator("#q").is_visible())
    pg.set_viewport_size({"width": 1320, "height": 860})
    # impact unreadable
    plat.perf = None; pg.click("#btn-refresh"); pg.wait_for_timeout(1500)
    ok("impact unreadable: cards say so and every row is n/a", "log needs admin" in pg.inner_text("#cards") and "High" not in pg.inner_text("#rows"), pg.inner_text("#cards"))
    ok("no console/page errors", not errors, errors[:3])
    b.close()
import shutil; shutil.rmtree(tmp, ignore_errors=True)
R.done()
