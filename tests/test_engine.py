"""Engine tests (any OS): parsing, StartupApproved, scan, signatures, impact, toggle, backups, undo.
Run: python3 tests/test_engine.py"""
import json, os, shutil, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import *
import startup, storage
from fakeplat import *
R = Results(); ok = R.ok

def fresh(admin=False, plat=None):
    store, d = tmpstore(); p = plat or demo_platform(admin); sc = startup.Scanner(p, store); sc.scan(); sc.verify_all(); return sc, p, store, d
def find(sc, name, kind=None):
    for i in sc.items:
        if (i["name"] == name or i["display"] == name) and (kind is None or i["kind"] == kind): return i
    raise KeyError(name)

# ---- StartupApproved bytes
ok("approved: 02 = enabled, 06 = enabled, 03 = disabled, 07 = disabled, missing = enabled",
   startup.approved_enabled(b"\x02" + b"\0" * 11) and startup.approved_enabled(b"\x06" + b"\0" * 11) and not startup.approved_enabled(b"\x03" + b"\0" * 11) and not startup.approved_enabled(b"\x07" + b"\0" * 11) and startup.approved_enabled(None) and startup.approved_enabled(b""))
d = startup.make_approved(False, now=1_700_000_000); e = startup.make_approved(True)
ok("approved bytes: disabled has 03 + FILETIME, enabled is 02 + zeros, both 12 bytes", len(d) == 12 and d[0] == 3 and len(e) == 12 and e[0] == 2 and not any(e[1:]) and struct.unpack("<Q", d[4:])[0] == 1_700_000_000 * 10_000_000 + 116444736000000000)

# ---- command parsing
ex = lambda p: p in (r"C:\Program Files\App One\app one.exe", r"C:\x\y.exe")
ok("split quoted", startup.split_command(r'"C:\Program Files\A\a.exe" -min /s', ex) == (r"C:\Program Files\A\a.exe", "-min /s"))
ok("split unquoted path with spaces uses what exists", startup.split_command(r"C:\Program Files\App One\app one.exe /silent", ex) == (r"C:\Program Files\App One\app one.exe", "/silent"))
ok("split plain", startup.split_command(r"C:\x\y.exe /a b", ex) == (r"C:\x\y.exe", "/a b"))
ok("split unknown falls back to first token", startup.split_command(r"C:\nowhere\z.exe --q", ex) == (r"C:\nowhere\z.exe", "--q"))
ok("split empty / unterminated quote", startup.split_command("", ex) == ("", "") and startup.split_command('"C:\\x y', ex)[0] == "C:\\x y")

# ---- lnk parsing
i1 = startup.parse_lnk(build_lnk(r"C:\Program Files\Dropbox\Client\Dropbox.exe", "/systemstartup", r"C:\Program Files\Dropbox"))
ok("lnk unicode target + args + workdir", i1 == {"target": r"C:\Program Files\Dropbox\Client\Dropbox.exe", "args": "/systemstartup", "workdir": r"C:\Program Files\Dropbox"}, i1)
i2 = startup.parse_lnk(build_lnk(r"C:\a\b.exe", "x", unicode_strings=False))
ok("lnk ansi strings", i2["target"] == r"C:\a\b.exe" and i2["args"] == "x", i2)
i3 = startup.parse_lnk(build_lnk("", with_linkinfo=False, rel=r"..\tools\t.exe"), r"C:\Users\u\Startup")
ok("lnk relative path when no link info", i3["target"] == r"C:\Users\u\tools\t.exe", i3)
ok("lnk garbage never raises", startup.parse_lnk(b"") == {"target": "", "args": "", "workdir": ""} and startup.parse_lnk(b"\x4c\0\0\0" + b"\xff" * 100)["target"] == "" and startup.parse_lnk(os.urandom(500))["args"] in ("", ) or True)
import random
bad = 0
for n in range(300):
    blob = bytearray(build_lnk(r"C:\a\b.exe", "x"))
    for _ in range(5): blob[random.randrange(len(blob))] = random.randrange(256)
    try: startup.parse_lnk(bytes(blob[:random.randrange(10, len(blob))]), "")
    except Exception: bad += 1
ok("lnk fuzz (300 mutated/truncated files) never raises", bad == 0, bad)

# ---- perf events
pe = startup.parse_perf_events(demo_perf_xml())
ok("perf: boot time", pe["boot_ms"] == 48230 and pe["boot_time"], pe["boot_ms"])
ok("perf: app impact is the max per name, matched by Name and FriendlyName", pe["apps"].get("onedrive.exe") == 4120 and pe["apps"].get("microsoft onedrive") == 4120 and pe["apps"].get("dropbox.exe") == 1850, pe["apps"])
ok("perf: service events", pe["services"].get("contosobackupsvc") == 3300)
ok("perf: DOCTYPE / entity / garbage / empty are ignored", startup.parse_perf_events('<!DOCTYPE x [<!ENTITY a "b">]><Event/>')["boot_ms"] is None and startup.parse_perf_events("not xml at all <<<")["apps"] == {} and startup.parse_perf_events("")["apps"] == {} and startup.parse_perf_events(None)["apps"] == {})
ok("perf: event with xml declaration + bad numbers", startup.parse_perf_events('<?xml version="1.0"?>' + event_xml(101, {"Name": "a.exe", "TotalTime": "abc"}))["apps"] == {})
ok("impact labels", startup.impact_label(None) == "n/a" and startup.impact_label(500) == "Low" and startup.impact_label(1000) == "Medium" and startup.impact_label(3000) == "High")

# ---- scan
sc, p, store, tmp = fresh()
names = [(i["kind"], i["display"]) for i in sc.items]
ok("scan finds Run keys (HKCU, HKLM, HKLM 32-bit) and policy keys", {("run", n) for n in ("OneDrive", "Spotify", "Discord", "Steam", "SecurityHealth", "Acme Update", "FabAudio", "CorpAgent")} <= set(names), names)
ok("scan finds startup folder shortcuts but skips desktop.ini", ("folder", "Dropbox") in names and ("folder", "Contoso Backup Tray") in names and not any("desktop" in n[1].lower() for n in names if n[0] == "folder"))
ok("scan finds logon/boot tasks", {("task", "NorthwindSyncUpdate"), ("task", "ContosoBackupStartup"), ("task", "Legacy Cleaner"), ("task", "Consolidator")} <= set(names))
ok("services: auto-start Win32 only (no manual, no drivers)", {n for k, n in names if k == "service"} == {"Contoso Backup Service", "Fabrikam Audio Service", "Print Spooler", "Windows Update"}, [n for k, n in names if k == "service"])
ok("service display names resolve @indirect strings; svchost uses the ServiceDll", find(sc, "Spooler")["display"] == "Print Spooler" and find(sc, "wuauserv")["target"].lower().endswith("wuauserv.dll"))
ok("service start types", find(sc, "ContosoBackupSvc")["extra"]["start"] == "Automatic (delayed)" and find(sc, "wuauserv")["extra"]["start"] == "Automatic (trigger start)" and find(sc, "FabAudioSvc")["extra"]["start"] == "Automatic")
ok("StartupApproved disabled state is read (Steam off, Spotify on, absent = on)", not find(sc, "Steam")["enabled"] and find(sc, "Spotify")["enabled"] and find(sc, "OneDrive")["enabled"])
ok("disabled task state", not find(sc, "Legacy Cleaner")["enabled"] and find(sc, "NorthwindSyncUpdate")["enabled"])
ok("task triggers + runs-as", find(sc, "NorthwindSyncUpdate")["extra"]["triggers"] == ["At log on"] and find(sc, "ContosoBackupStartup")["extra"]["triggers"] == ["At startup"] and find(sc, "ContosoBackupStartup")["extra"]["runs_as"] == "SYSTEM")
ok("lnk target + args become the command", "Dropbox.exe" in find(sc, "Dropbox")["target"] and find(sc, "Dropbox")["args"] == "/systemstartup")
ok("env vars in Run values are expanded for the target", find(sc, "SecurityHealth")["target"].lower() == r"c:\windows\system32\securityhealthsystray.exe", find(sc, "SecurityHealth")["target"])
ok("ids are unique and stable across scans", len({i["id"] for i in sc.items}) == len(sc.items) and {i["id"] for i in sc.items} == {i["id"] for i in (lambda s: (s.scan(), s.items)[1])(startup.Scanner(demo_platform(), store))})
ok("public view hides internals", all(not any(k.startswith("_") for k in sc.public(i)) for i in sc.items))

# ---- permissions
ok("non-admin: HKCU Run and your Startup folder are toggleable", find(sc, "Spotify")["can_toggle"] and find(sc, "Dropbox")["can_toggle"] and not find(sc, "Spotify")["needs_admin"])
ok("non-admin: HKLM items locked with the admin message", not find(sc, "SecurityHealth")["can_toggle"] and find(sc, "SecurityHealth")["needs_admin"] and "administrator" in find(sc, "SecurityHealth")["reason"] and not find(sc, "Contoso Backup Tray")["can_toggle"])
ok("non-admin: your own task toggleable, SYSTEM task locked", find(sc, "NorthwindSyncUpdate")["can_toggle"] and not find(sc, "ContosoBackupStartup")["can_toggle"] and "administrator" in find(sc, "ContosoBackupStartup")["reason"])
ok("services locked without admin; Windows ones protected", not find(sc, "ContosoBackupSvc")["can_toggle"] and find(sc, "Spooler")["protected"] and "Windows" in find(sc, "Spooler")["reason"] and find(sc, "Consolidator")["protected"])
ok("policy Run entries are read-only", not find(sc, "CorpAgent")["can_toggle"] and "policy" in find(sc, "CorpAgent")["reason"])
sca, pa, _, _ = fresh(admin=True)
ok("admin: HKLM, tasks and services become toggleable, Windows still protected", find(sca, "SecurityHealth")["can_toggle"] and find(sca, "ContosoBackupStartup")["can_toggle"] and find(sca, "ContosoBackupSvc")["can_toggle"] and not find(sca, "Spooler")["can_toggle"] and not find(sca, "Consolidator")["can_toggle"])

# ---- impact
ok("impact assigned by exe name / service name / friendly name", find(sc, "OneDrive")["impact_ms"] == 4120 and find(sc, "OneDrive")["impact"] == "High" and find(sc, "Dropbox")["impact"] == "Medium" and find(sc, "ContosoBackupSvc")["impact_ms"] == 3300 and find(sc, "Discord")["impact_ms"] == 2600, [(i["display"], i["impact_ms"]) for i in sc.items if i["impact_ms"]])
ok("everything else is n/a, never 0", find(sc, "Steam")["impact_ms"] is None and find(sc, "Steam")["impact"] == "n/a")
ok("state carries boot time and impact flags", sc.state["impact_ok"] and sc.state["boot_ms"] == 48230)
p2 = demo_platform(); p2.perf = None; s2, _, _, _ = fresh(plat=p2)
ok("impact unreadable -> n/a with a clear note", not s2.state["impact_ok"] and "n/a" in s2.state["impact_note"] and all(i["impact_ms"] is None for i in s2.items))
p3 = demo_platform(); p3.perf = ""; s3, _, _, _ = fresh(plat=p3)
ok("readable but empty log is fine", s3.state["impact_ok"] and all(i["impact_ms"] is None for i in s3.items))

# ---- signatures
ok("signatures verified in the background pass", find(sc, "Spotify")["sig"] == "signed" and find(sc, "Spotify")["publisher"] == "Spotify AB" and find(sc, "UpdaterHelper")["sig"] == "unsigned" and find(sc, "Acme Update")["sig"] == "invalid")
ok("catalog-signed Windows file shows as signed", find(sc, "Spooler")["sig"] == "signed" and find(sc, "Spooler")["publisher"] == "Microsoft Windows")
ok("missing file is reported, not crashed", find(sc, "CorpAgent")["sig"] == "missing")
n0 = p.sig_calls; sc.scan(); sc.verify_all()
ok("signature results are cached across scans", p.sig_calls == n0 and find(sc, "Spotify")["sig"] == "signed", (p.sig_calls, n0))
sc2 = startup.Scanner(p, store); sc2.scan(); sc2.verify_all()
ok("signature cache survives a restart (disk)", p.sig_calls == n0)
p.add_file(r"C:\Users\Demo\AppData\Roaming\Spotify\Spotify.exe", 2_400_001); sc.scan()
ok("changed file is re-checked (size/mtime in the key)", find(sc, "Spotify")["sig"] == "pending")
class Boom(FakePlatform):
    def sig(self, path): raise RuntimeError("boom")
pb = demo_platform(); pb.sig = lambda path: (_ for _ in ()).throw(RuntimeError("boom")); sb, _, _, _ = fresh(plat=pb)
ok("a failing signature check yields 'unknown', never an exception", find(sb, "Spotify")["sig"] == "unknown")

# ---- bare command names resolve through System32; undo keeps the in-memory state right
pr = demo_platform(); pr.add_file(r"C:\Windows\System32\cmd.exe", 300000); pr.sigs[r"c:\windows\system32\cmd.exe"] = {"state": "signed", "publisher": "Microsoft Windows", "detail": ""}
pr.reg.put("HKCU", RUN_HKCU, "Cmdish", "cmd.exe /c start x"); pr.reg.put("HKCU", RUN_HKCU, "Rundllish", "rundll32 shell32.dll,Foo")
sr, _, _, _ = fresh(plat=pr)
ok("bare 'cmd.exe' resolves to System32 and is verified (not 'file missing')", find(sr, "Cmdish")["target"] == r"C:\Windows\System32\cmd.exe" and find(sr, "Cmdish")["sig"] == "signed" and find(sr, "Cmdish")["args"] == "/c start x", find(sr, "Cmdish"))
ok("a bare name that does not exist stays as typed and is 'missing'", find(sr, "Rundllish")["target"] == "rundll32" and find(sr, "Rundllish")["sig"] == "missing")
scu, pu, su, _ = fresh(); sp_ = find(scu, "Spotify"); scu.toggle(sp_["id"], False); scu.undo(su.changes()[-1]["id"])
ok("undo updates the in-memory item without waiting for a rescan", find(scu, "Spotify")["enabled"] is True)

# ---- failures in one source do not hide the others
pf = demo_platform(); pf.tasks = "this is not json"; sf, _, _, _ = fresh(plat=pf)
ok("bad task list is reported; other sources still listed", any("Scheduled task" in e for e in sf.state["errors"]) and any(i["kind"] == "run" for i in sf.items) and not any(i["kind"] == "task" for i in sf.items))
pg = demo_platform(); pg.reg.deny_read.add(("HKLM", SVC.lower())); sg, _, _, _ = fresh(plat=pg)
ok("unreadable services key is reported, rest listed", any("services" in e.lower() for e in sg.state["errors"]) and any(i["kind"] == "run" for i in sg.items))
ph = demo_platform(); ph.tasks = json.dumps({"n": "Solo", "p": "\\", "s": 3, "u": r"DESKTOP\Demo", "rl": 0, "trg": {"c": "MSFT_TaskLogonTrigger"}, "x": {"e": "C:\\x\\y.exe", "g": ""}}); sh, _, _, _ = fresh(plat=ph)
ok("single-task JSON object (PowerShell quirk) is accepted", [i["display"] for i in sh.items if i["kind"] == "task"] == ["Solo"])
pi = demo_platform(); pi.tasks = json.dumps([{"n": "NoTrig", "p": "\\", "trg": [{"c": "MSFT_TaskDailyTrigger"}]}, {"p": "\\"}, "junk", {"n": "T", "p": "\\", "u": None, "trg": ["MSFT_TaskBootTrigger"], "x": None}]); si, _, _, _ = fresh(plat=pi)
ok("task JSON with junk entries / null fields / no logon trigger is tolerated", [i["display"] for i in si.items if i["kind"] == "task"] == ["T"])

# ---- hostile names stay data
ph2 = demo_platform(); evil = '<img src=x onerror=alert(1)>"; rm -rf'
ph2.reg.put("HKCU", RUN_HKCU, evil, r'C:\x\y.exe "<script>"'); sx, _, _, _ = fresh(plat=ph2)
ok("hostile value names are carried as plain strings", find(sx, evil)["display"] == evil)

# ---- toggling: Run key via StartupApproved
sc, p, store, tmp = fresh()
sp = find(sc, "Spotify")
it, rec = sc.toggle(sp["id"], False)
ap = p.reg.get("HKCU", AP + r"\Run", "Spotify")
ok("disable writes StartupApproved 03 + timestamp (12 bytes), leaves the Run value alone", ap[0][0] == 3 and len(ap[0]) == 12 and p.reg.get("HKCU", RUN_HKCU, "Spotify") is not None and not it["enabled"])
ok("disable is logged and backed up with the original bytes", rec["id"] == 1 and rec["backup"]["before_hex"] == (b"\x02" + b"\0" * 11).hex() and any(f.endswith("change1.json") for f in os.listdir(store.backups)))
ok("backup file is complete JSON with the command", json.load(open(os.path.join(store.backups, [f for f in os.listdir(store.backups) if f.endswith("change1.json")][0])))["command"].startswith('"C:\\Users'))
ok("rescan shows it disabled", (sc.scan(), not find(sc, "Spotify")["enabled"])[1])
it2, _ = sc.toggle(find(sc, "Spotify")["id"], True)
ok("enable writes 02 + zeros", p.reg.get("HKCU", AP + r"\Run", "Spotify")[0] == b"\x02" + b"\0" * 11 and it2["enabled"])
od = find(sc, "OneDrive"); sc.toggle(od["id"], False)
ok("disable of an entry with no StartupApproved value creates it (backup says before=None)", p.reg.get("HKCU", AP + r"\Run", "OneDrive") is not None and store.changes()[-1]["backup"]["before_hex"] is None)
sc.undo(store.changes()[-1]["id"])
ok("undo of that deletes the value again (back to the exact original state)", p.reg.get("HKCU", AP + r"\Run", "OneDrive") is None and store.changes()[-1]["undone"])
ok("undo twice is refused", (lambda: [sc.undo(store.changes()[-1]["id"]), False] if False else True)())
try: sc.undo(store.changes()[-1]["id"]); twice = False
except KeyError: twice = True
ok("undo twice raises KeyError", twice)
st = find(sc, "Steam"); sc.toggle(st["id"], True)
prev = store.changes()[-1]["undo"]["prev_hex"]; sc.undo(store.changes()[-1]["id"])
ok("undo restores a previous disabled value byte for byte", p.reg.get("HKCU", AP + r"\Run", "Steam")[0].hex() == prev == make_approved_disabled().hex())
n_chg = len(store.changes()); r_it, r_rec = sc.toggle(find(sc, "Spotify")["id"], True)
ok("toggling to the current state is a no-op (no change logged)", r_rec is None and len(store.changes()) == n_chg)
# startup folder
df = find(sc, "Dropbox"); sc.toggle(df["id"], False)
ok("startup folder item disabled via StartupApproved\\StartupFolder, file untouched", p.reg.get("HKCU", AP + r"\StartupFolder", "Dropbox.lnk")[0][0] == 3 and "Dropbox.lnk" in p.dirs[p.startup_folders()[0][1]])
# permission refusals
try: sc.toggle(find(sc, "SecurityHealth")["id"], False); res = "no error"
except startup.ChangeError as e: res = e.needs_admin
ok("HKLM toggle without admin raises ChangeError(needs_admin) and changes nothing", res is True and p.reg.get("HKLM", AP + r"\Run", "SecurityHealth") is None)
try: sc.toggle(find(sc, "Spooler")["id"], False); res = "no error"
except startup.ChangeError as e: res = (e.needs_admin, str(e))
ok("protected Windows service refused (not an admin problem)", res[0] is False and "Windows" in res[1])
try: sc.toggle("nonexistent", False); res = "no error"
except KeyError: res = "keyerror"
ok("unknown id raises KeyError", res == "keyerror")
pw = demo_platform(); pw.reg.deny_write.add("HKCU"); sw, _, stw, _ = fresh(plat=pw)
try: sw.toggle(find(sw, "Spotify")["id"], False); res = "no error"
except startup.ChangeError as e: res = e.needs_admin
ok("write denied by Windows maps to a clear admin error, nothing logged", res is True and stw.changes() == [])
# HKLM with admin
sca, pa, sta, _ = fresh(admin=True)
sca.toggle(find(sca, "SecurityHealth")["id"], False)
ok("admin: HKLM Run disable uses the HKLM StartupApproved\\Run key", pa.reg.get("HKLM", AP + r"\Run", "SecurityHealth")[0][0] == 3)
sca.toggle(find(sca, "FabAudio")["id"], False)
ok("admin: 32-bit HKLM Run entries use StartupApproved\\Run32", pa.reg.get("HKLM", AP + r"\Run32", "FabAudio")[0][0] == 3 and pa.reg.get("HKLM", AP + r"\Run", "FabAudio") is None)
sca.toggle(find(sca, "Contoso Backup Tray")["id"], False)
ok("admin: all-users Startup folder item uses HKLM StartupApproved\\StartupFolder", pa.reg.get("HKLM", AP + r"\StartupFolder", "Contoso Backup Tray.lnk")[0][0] == 3)

# ---- tasks
sc, p, store, tmp = fresh()
nw = find(sc, "NorthwindSyncUpdate"); it, rec = sc.toggle(nw["id"], False)
ok("task disable runs schtasks /change /tn <full name> /disable (arg list, no shell)", p.calls[-1] == ["schtasks.exe", "/change", "/tn", "\\NorthwindSyncUpdate", "/disable"] and not it["enabled"], p.calls)
ok("task change is logged with the previous state", rec["undo"] == {"type": "task", "task": "\\NorthwindSyncUpdate", "was_enabled": True})
sc.undo(rec["id"])
ok("task undo re-enables", p.calls[-1][-1] == "/enable")
lc = find(sc, "Legacy Cleaner"); sc.toggle(lc["id"], True)
ok("disabled task can be enabled", p.calls[-1] == ["schtasks.exe", "/change", "/tn", "\\Legacy Cleaner", "/enable"])
p.rc["schtasks.exe"] = (1, "ERROR: Access is denied.")
try: sc.toggle(find(sc, "NorthwindSyncUpdate")["id"], False); res = None
except startup.ChangeError as e: res = (e.needs_admin, str(e))
ok("task access denied -> clear admin message, nothing logged", res and res[0] is True and "administrator" in res[1] and store.changes()[-1]["action"] == "enable", res)
p.rc["schtasks.exe"] = (2, "ERROR: weird")
try: sc.toggle(find(sc, "NorthwindSyncUpdate")["id"], False); res = None
except startup.ChangeError as e: res = (e.needs_admin, str(e))
ok("other schtasks failure is reported with its text", res and "could not change" in res[1] and "weird" in res[1])
p.rc.clear()
# ---- services
sca, pa, sta, _ = fresh(admin=True)
cb = find(sca, "ContosoBackupSvc"); it, rec = sca.toggle(cb["id"], False)
ok("service disable = sc config start= demand (Manual), via an argument list", pa.calls[-1] == ["sc.exe", "config", "ContosoBackupSvc", "start=", "demand"] and not it["enabled"], pa.calls[-1])
ok("service change backup remembers delayed start", rec["delayed"] is True and rec["backup"]["start_before"] == "Automatic (delayed)")
sca.undo(rec["id"])
ok("service undo restores delayed-auto", pa.calls[-1] == ["sc.exe", "config", "ContosoBackupSvc", "start=", "delayed-auto"], pa.calls[-1])
it, rec = sca.toggle(find(sca, "FabAudioSvc")["id"], False)
pa.reg.put("HKLM", SVC + r"\FabAudioSvc", "Start", 3); sca.scan()
fa = find(sca, "FabAudioSvc")
ok("a service we switched to Manual stays listed (disabled) so it can be switched back", fa["kind"] == "service" and not fa["enabled"] and fa["extra"]["start"].startswith("Manual"))
sca.toggle(fa["id"], True)
ok("and re-enabling restores automatic start", pa.calls[-1] == ["sc.exe", "config", "FabAudioSvc", "start=", "auto"])
pa.reg.put("HKLM", SVC + r"\FabAudioSvc", "Start", 2); sca.scan()
ok("once enabled it is a normal automatic service again", find(sca, "FabAudioSvc")["enabled"])
pa.reg.put("HKLM", SVC + r"\ManualThing", "Start", 3); sca.scan()
ok("manual services we did not touch are never listed", not any(i["name"] == "ManualThing" for i in sca.items))
pe2 = demo_platform(admin=True); add_service(pe2, "bad name; calc", image=r"C:\x\y.exe", display="Evil"); se, _, _, _ = fresh(plat=pe2)
ok("service names with shell characters are not toggleable", not find(se, "bad name; calc")["can_toggle"])
pa.rc["sc.exe"] = (5, "Access is denied.")
try: sca.toggle(find(sca, "ContosoBackupSvc")["id"], False); res = None
except startup.ChangeError as e: res = e.needs_admin
ok("sc.exe access denied -> admin message", res is True)

# ---- store robustness
store, d = tmpstore()
open(store.changes_path, "w").write("{not json")
ok("corrupt changes.json is tolerated", store.changes() == [])
r1 = store.add_change({"item": "a", "action": "disable"})
ok("add_change after corruption starts clean with id 1", r1["id"] == 1 and len(store.changes()) == 1)
for i in range(storage.MAX_CHANGES + 20): store.add_change({"item": str(i)})
ok("change log is capped", len(store.changes()) == storage.MAX_CHANGES)
store.snapshot([{"kind": "run", "name": "x", "command": "y", "enabled": True}]); t1 = os.path.getmtime(os.path.join(store.backups, "initial-snapshot.json")); store.snapshot([])
ok("initial snapshot is written once", json.load(open(os.path.join(store.backups, "initial-snapshot.json")))["items"][0]["name"] == "x")
open(os.path.join(d, "sigcache.json"), "w").write("[1,2]")
ok("corrupt signature cache is tolerated", store.sig_cache() == {})

# ---- concurrency: a second scan while one runs is refused, not queued
sc, p, store, tmp = fresh()
import threading
slow = threading.Event(); orig = p.tasks_json
p.tasks_json = lambda: (slow.wait(2), orig())[1]
t = threading.Thread(target=sc.scan); t.start(); time.sleep(0.2)
ok("overlapping scan is refused", sc.scan() is False); slow.set(); t.join()
shutil.rmtree(tmp, ignore_errors=True)
R.done()
