"""Windows-only checks against the REAL machine, touching only things this test creates (names start with
StartupScopeTest-). Run with the build python:  python tests\\test_windows.py   (no admin needed)."""
import json, os, subprocess, sys, tempfile, time, uuid
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import *
if os.name != "nt": print("SKIP: Windows only"); raise SystemExit(0)
import startup, storage, winapi
R = Results(); ok = R.ok
tag = "StartupScopeTest-" + uuid.uuid4().hex[:8]
plat = winapi.WinPlatform(); store, tmp = tmpstore()
RUNK = r"Software\Microsoft\Windows\CurrentVersion\Run"; APK = startup.AP_BASE + r"\Run"
import winreg
def cleanup():
    for hive, key in (("HKCU", RUNK), ("HKCU", APK), ("HKCU", startup.AP_BASE + r"\StartupFolder")):
        try: plat.reg.delete_value(hive, key, tag); plat.reg.delete_value(hive, key, tag + ".lnk")
        except Exception: pass
    sf = plat.startup_folders()[0][1]
    for f in (tag + ".lnk",):
        try: os.remove(os.path.join(sf, f))
        except OSError: pass
    subprocess.run(["powershell.exe", "-NoProfile", "-Command", "Unregister-ScheduledTask -TaskName '%s' -Confirm:$false -ErrorAction SilentlyContinue" % tag], capture_output=True, creationflags=winapi.NO_WINDOW)
try:
    ok("registry wrapper reads real values (HKCU Run exists as a key)", isinstance(plat.reg.values("HKCU", RUNK), dict))
    ok("services are readable without admin", len(plat.reg.subkeys("HKLM", startup.SERVICES_KEY)) > 50)
    ok("is_admin returns a bool", plat.is_admin() in (True, False))
    # --- own Run value + StartupApproved round trip
    test_exe = os.path.join(tempfile.gettempdir(), tag + ".exe")
    open(test_exe, "wb").write(b"MZ not a real program")
    w = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUNK, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY); winreg.SetValueEx(w, tag, 0, winreg.REG_SZ, '"%s" --tray' % test_exe); winreg.CloseKey(w)
    # --- own startup-folder shortcut (real .lnk made by Windows)
    sf = plat.startup_folders()[0][1]; os.makedirs(sf, exist_ok=True)
    lnk = os.path.join(sf, tag + ".lnk")
    subprocess.run(["powershell.exe", "-NoProfile", "-Command", "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%s'); $s.TargetPath='%s'; $s.Arguments='--hello world'; $s.Save()" % (lnk, test_exe)], capture_output=True, creationflags=winapi.NO_WINDOW)
    # --- own scheduled task with a logon trigger (current user, limited, no admin)
    mk = ("$a=New-ScheduledTaskAction -Execute '%s' -Argument '--task'; $t=New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME; "
          "$p=New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited; Register-ScheduledTask -TaskName '%s' -Action $a -Trigger $t -Principal $p | Out-Null" % (test_exe, tag))
    rr = subprocess.run(["powershell.exe", "-NoProfile", "-Command", mk], capture_output=True, creationflags=winapi.NO_WINDOW, timeout=60)
    task_ok = rr.returncode == 0
    sc = startup.Scanner(plat, store); t0 = time.time(); sc.scan(); scan_s = time.time() - t0; sc.verify_all()
    kinds = {}
    for i in sc.items: kinds[i["kind"]] = kinds.get(i["kind"], 0) + 1
    print("INFO scan took %.1f s, items: %s, errors: %s" % (scan_s, kinds, sc.state["errors"]))
    ok("scan finds items of every kind on this PC", all(kinds.get(k, 0) > 0 for k in ("run", "service")) and sum(kinds.values()) > 10, kinds)
    by = {i["name"]: i for i in sc.items}
    r1 = by.get(tag); ok("our Run value is listed, enabled, toggleable", r1 and r1["enabled"] and r1["can_toggle"] and r1["target"].lower() == test_exe.lower() and r1["args"] == "--tray", r1)
    ok("our unsigned test file is reported unsigned", r1["sig"] == "unsigned", (r1["sig"], r1["sig_detail"]))
    f1 = by.get(tag + ".lnk"); ok("our Startup-folder .lnk (made by Windows) is parsed: target + args", f1 and f1["target"].lower() == test_exe.lower() and f1["args"] == "--hello world", f1)
    t1 = by.get("\\" + tag); ok("our logon task is listed with trigger and owner", (not task_ok) or (t1 and t1["extra"]["triggers"] == ["At log on"] and t1["can_toggle"] and t1["enabled"] and t1["target"].lower() == test_exe.lower()), t1 or rr.stderr[:200])
    # --- toggles
    it, rec = sc.toggle(r1["id"], False)
    raw = plat.reg.get("HKCU", APK, tag)
    ok("Run: StartupApproved\\Run value written as REG_BINARY 03 + FILETIME", raw and raw[1] == "binary" and raw[0][0] == 3 and len(raw[0]) == 12, raw)
    sc.scan(); ok("Run: rescan reads it back as disabled", not {i["name"]: i for i in sc.items}[tag]["enabled"])
    ok("Run: Explorer's own view agrees (value still present in Run)", plat.reg.get("HKCU", RUNK, tag) is not None)
    sc.undo(rec["id"]); ok("Run: undo removes our StartupApproved value again", plat.reg.get("HKCU", APK, tag) is None and sc.by_id[r1["id"]]["enabled"])
    it, rec2 = sc.toggle(f1["id"], False); fraw = plat.reg.get("HKCU", startup.AP_BASE + r"\StartupFolder", tag + ".lnk")
    ok("Folder: StartupApproved\\StartupFolder written; shortcut file untouched", fraw and fraw[0][0] == 3 and os.path.isfile(lnk))
    sc.undo(rec2["id"]); ok("Folder: undo", plat.reg.get("HKCU", startup.AP_BASE + r"\StartupFolder", tag + ".lnk") is None)
    if task_ok:
        sc.scan(); t1 = {i["name"]: i for i in sc.items}["\\" + tag]
        it, rec3 = sc.toggle(t1["id"], False)
        sc.scan(); ok("Task: schtasks /disable works and the rescan sees it disabled", not {i["name"]: i for i in sc.items}["\\" + tag]["enabled"])
        sc.undo(rec3["id"]); sc.scan(); ok("Task: undo re-enables", {i["name"]: i for i in sc.items}["\\" + tag]["enabled"])
    # --- locked things are really locked without admin
    if not plat.is_admin():
        hk = next((i for i in sc.items if i["source"] == "HKLM Run"), None)
        ok("HKLM Run item is locked (needs admin) when not elevated", hk is None or (not hk["can_toggle"] and hk["needs_admin"]))
        sv = next((i for i in sc.items if i["kind"] == "service" and not i["protected"]), None)
        ok("third-party service is locked when not elevated", sv is None or not sv["can_toggle"])
        try: plat.reg.set_binary("HKLM", startup.AP_BASE + r"\Run", tag, b"\x03" + b"\0" * 11); denied = False
        except PermissionError: denied = True
        ok("HKLM StartupApproved write is really denied without admin (-> PermissionError)", denied)
        try: plat.reg.delete_value("HKLM", startup.AP_BASE + r"\Run", tag)
        except PermissionError: pass
    # --- signatures on real files
    win = os.environ.get("SystemRoot", r"C:\Windows")
    s1 = plat.sig(os.path.join(win, "System32", "notepad.exe")); ok("catalog/embedded: notepad.exe is signed by Microsoft", s1["state"] == "signed" and "microsoft" in (s1["publisher"] or "").lower(), s1)
    s2 = plat.sig(os.path.join(win, "System32", "kernel32.dll")); ok("kernel32.dll is signed", s2["state"] == "signed", s2)
    edge = next((os.path.join(b, "Microsoft", "Edge", "Application", "msedge.exe") for b in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")) if b and os.path.isfile(os.path.join(b, "Microsoft", "Edge", "Application", "msedge.exe"))), None)
    if edge:
        s3 = plat.sig(edge); ok("embedded Authenticode: msedge.exe signed, publisher from the signing certificate", s3["state"] == "signed" and "microsoft" in (s3["publisher"] or "").lower(), s3)
    s4 = plat.sig(test_exe); ok("unsigned file -> unsigned", s4["state"] == "unsigned", s4)
    tampered = os.path.join(tempfile.gettempdir(), tag + "-t.exe"); data = bytearray(open(os.path.join(win, "System32", "notepad.exe"), "rb").read()); data[-200] ^= 0xFF; data[1000] ^= 0xFF
    open(tampered, "wb").write(bytes(data)); s5 = plat.sig(tampered); os.remove(tampered)
    ok("modified copy of a signed file is not reported as signed", s5["state"] in ("invalid", "unsigned"), s5)
    ok("company_name from version info", "microsoft" in winapi.company_name(os.path.join(win, "System32", "notepad.exe")).lower())
    ok("a missing/odd path never raises", plat.sig(os.path.join(tempfile.gettempdir(), "nope-" + tag + ".exe"))["state"] in ("unsigned", "unknown", "invalid"))
    # --- event log
    t0 = time.time(); xml = plat.perf_events_xml(); print("INFO perf log: %s (%.1f s)" % ("readable, %d chars" % len(xml) if xml is not None else "not readable without admin", time.time() - t0))
    pe = startup.parse_perf_events(xml or "") if xml else None
    ok("Diagnostics-Performance log is either readable and parseable, or cleanly n/a", xml is None or isinstance(pe["apps"], dict))
    if pe: print("INFO boot_ms=%s apps=%d services=%d" % (pe["boot_ms"], len(pe["apps"]), len(pe["services"])))
    ok("service display names resolve (no raw '@%' resource strings left)", not any(i["display"].startswith("@") for i in sc.items if i["kind"] == "service"))
    ok("every item has a command or location and a stable id", all(i["id"] and (i["command"] or i["location"]) for i in sc.items))
finally:
    cleanup()
    try: os.remove(os.path.join(tempfile.gettempdir(), tag + ".exe"))
    except OSError: pass
leftover = plat.reg.get("HKCU", RUNK, tag) or plat.reg.get("HKCU", APK, tag)
ok("cleanup: no test values left behind", leftover is None)
R.done()
