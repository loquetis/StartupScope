"""A fake Windows for tests and screenshots: in-memory registry, files, signatures and command results."""
import json, os, struct, time

class FakeReg:
    def __init__(self):
        self.d = {}                   # (hive, path.lower()) -> {name: (data, type)}
        self.deny_write = set()       # hives where writes raise PermissionError
        self.orig = {}
        self.deny_read = set()        # (hive, path.lower()) that raise PermissionError when read
    def put(self, hive, path, name, data, typ=None):
        self.orig[(hive, path.lower())] = path
        typ = typ or ("dword" if isinstance(data, int) else "binary" if isinstance(data, (bytes, bytearray)) else "sz")
        self.d.setdefault((hive, path.lower()), {})[name] = (data, typ)
    def values(self, hive, path):
        if (hive, path.lower()) in self.deny_read: raise PermissionError(path)
        return dict(self.d.get((hive, path.lower()), {}))
    def get(self, hive, path, name):
        return self.d.get((hive, path.lower()), {}).get(name)
    def subkeys(self, hive, path):
        if (hive, path.lower()) in self.deny_read: raise PermissionError(path)
        pre = path.lower() + "\\"; out = []
        for (h, p), orig in self.orig.items():
            if h == hive and p.startswith(pre):
                n = orig[len(pre):].split("\\")[0]
                if n not in out: out.append(n)
        return out
    def set_binary(self, hive, path, name, data):
        if hive in self.deny_write: raise PermissionError(path)
        self.d.setdefault((hive, path.lower()), {})[name] = (bytes(data), "binary")
    def delete_value(self, hive, path, name):
        if hive in self.deny_write: raise PermissionError(path)
        self.d.get((hive, path.lower()), {}).pop(name, None)

def build_lnk(target, args="", workdir="", unicode_strings=True, with_linkinfo=True, rel=None):
    flags = 0x80 if unicode_strings else 0
    if with_linkinfo: flags |= 2
    if args: flags |= 0x20
    if workdir: flags |= 0x10
    if rel: flags |= 0x08
    hdr = struct.pack("<I16sI", 0x4C, b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46", flags) + b"\x00" * (76 - 24)
    body = b""
    if with_linkinfo:
        tb = target.encode("mbcs" if False else "latin-1") + b"\x00"; suf = b"\x00"
        tu = target.encode("utf-16-le") + b"\x00\x00"; su = b"\x00\x00"
        hsize = 0x24; vol = hsize
        volid = struct.pack("<IIII", 16 + 1, 3, 0, 16) + b"\x00"   # tiny VolumeID
        lbp = vol + len(volid); cps = lbp + len(tb); lbpu = cps + len(suf); cpsu = lbpu + len(tu)
        total = cpsu + len(su)
        info = struct.pack("<IIIIIIIII", total, hsize, 1, vol, lbp, 0, cps, lbpu, cpsu) + volid + tb + suf + tu + su
        body += info
    def s(v):
        return struct.pack("<H", len(v)) + (v.encode("utf-16-le") if unicode_strings else v.encode("latin-1"))
    if rel: body += s(rel)
    if workdir: body += s(workdir)
    if args: body += s(args)
    return hdr + body

class FakePlatform:
    fake_windows = True
    def __init__(self, admin=False):
        self.reg = FakeReg()
        self._admin = admin; self.windir_ = r"C:\Windows"
        self.files = {}               # path -> (bytes_or_size, mtime)
        self.dirs = {}                # folder -> [file names]
        self.sigs = {}                # path.lower() -> dict
        self.tasks = ""; self.perf = None; self.user = r"DESKTOP\Demo"
        self.calls = []; self.rc = {}  # command exe -> (rc, text)
        self.revealed = []; self.sig_calls = 0
        self.indirect = {}
    def is_admin(self): return self._admin
    def current_user(self): return self.user
    def windir(self): return self.windir_
    def expand(self, s): return (s or "").replace("%SystemRoot%", self.windir_).replace("%windir%", self.windir_).replace("%ProgramFiles%", r"C:\Program Files")
    def exists(self, p): return p.lower() in {k.lower() for k in self.files}
    def isdir(self, p): return p in self.dirs
    def which(self, name):
        for d in (self.windir_ + r"\System32", self.windir_):
            for c in (name, name + ".exe"):
                if self.exists(d + "\\" + c): return d + "\\" + c
        return None
    def stat(self, p):
        for k, (b, m) in self.files.items():
            if k.lower() == (p or "").lower(): return (len(b) if isinstance(b, (bytes, bytearray)) else b, m)
        return None
    def list_dir(self, p):
        if p not in self.dirs: raise FileNotFoundError(p)
        return list(self.dirs[p])
    def read_file(self, p, limit):
        b = self.files[p][0]
        if not isinstance(b, (bytes, bytearray)): raise OSError("no data")
        return b[:limit]
    def startup_folders(self):
        return [("HKCU", r"C:\Users\Demo\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup", "Startup folder (you)"),
                ("HKLM", r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "Startup folder (all users)")]
    def tasks_json(self): return self.tasks
    def perf_events_xml(self): return self.perf
    def indirect_string(self, s): return self.indirect.get(s, "")
    def run(self, args, timeout=60):
        self.calls.append(list(args)); return self.rc.get(os.path.basename(args[0]).lower(), (0, ""))
    def reveal(self, p): self.revealed.append(p)
    def sig(self, path):
        self.sig_calls += 1
        return self.sigs.get(path.lower(), {"state": "unsigned", "publisher": "", "detail": "No digital signature"})
    # helpers to build fixtures
    def add_file(self, path, size=1000, mtime=1_700_000_000): self.files[path] = (size, mtime)
    def add_dirfile(self, folder, name, data):
        self.dirs.setdefault(folder, []).append(name); self.files[folder + "\\" + name] = (data, 1_700_000_000)

RUN_HKCU = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_HKLM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
RUN_WOW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
AP = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
SVC = r"SYSTEM\CurrentControlSet\Services"

def add_service(p, name, start=2, typ=0x10, image=None, display=None, delayed=False, desc=None, obj="LocalSystem", dll=None, trigger=False):
    path = SVC + "\\" + name
    p.reg.put("HKLM", path, "Start", start); p.reg.put("HKLM", path, "Type", typ)
    if image: p.reg.put("HKLM", path, "ImagePath", image, "expand_sz" if "%" in image else "sz")
    if display: p.reg.put("HKLM", path, "DisplayName", display)
    if desc: p.reg.put("HKLM", path, "Description", desc)
    p.reg.put("HKLM", path, "ObjectName", obj)
    if delayed: p.reg.put("HKLM", path, "DelayedAutostart", 1)
    if dll: p.reg.put("HKLM", path + r"\Parameters", "ServiceDll", dll, "expand_sz")
    if trigger: p.reg.put("HKLM", path + r"\TriggerInfo", "x", 1)

def demo_platform(admin=False):
    """A realistic, harmless demo PC (made-up vendors plus a few well-known apps). Used by tests and screenshots."""
    p = FakePlatform(admin)
    P = r"C:\Program Files"
    def exe(path, sig=None, size=2_400_000): p.add_file(path, size); p.sigs[path.lower()] = sig
    MS = {"state": "signed", "publisher": "Microsoft Corporation", "detail": "Valid digital signature"}
    def S(pub): return {"state": "signed", "publisher": pub, "detail": "Valid digital signature"}
    U = {"state": "unsigned", "publisher": "", "detail": "No digital signature"}
    exe(r"C:\Users\Demo\AppData\Local\Microsoft\OneDrive\OneDrive.exe", MS)
    exe(r"C:\Users\Demo\AppData\Roaming\Spotify\Spotify.exe", S("Spotify AB"))
    exe(r"C:\Users\Demo\AppData\Local\Discord\Update.exe", S("Discord Inc."))
    exe(P + r"\Steam\steam.exe", S("Valve Corp."))
    exe(r"C:\Users\Demo\AppData\Local\Programs\Northwind Sync\nwsync.exe", S("Northwind Software Ltd"))
    exe(r"C:\Users\Demo\AppData\Local\Temp\updater_helper.exe", U, 310_000)
    exe(r"C:\Windows\System32\SecurityHealthSystray.exe", MS)
    exe(P + r"\Fabrikam Audio\FabAudioMgr.exe", S("Fabrikam Inc."))
    exe(P + r"\Contoso Backup\cbtray.exe", S("Contoso Ltd."))
    exe(P + r"\Dropbox\Client\Dropbox.exe", S("Dropbox, Inc."))
    exe(P + r"\Contoso Backup\cbservice.exe", S("Contoso Ltd."))
    exe(P + r"\Fabrikam Audio\fabsvc.exe", S("Fabrikam Inc."))
    exe(r"C:\Windows\System32\spoolsv.exe", {"state": "signed", "publisher": "Microsoft Windows", "detail": "Signed through a Windows security catalog"})
    exe(P + r"\Common Files\Acme\AcmeUpdate.exe", {"state": "invalid", "publisher": "Acme Corp", "detail": "The file was changed after it was signed"}, 880_000)
    exe(r"C:\Windows\System32\svchost.exe", MS); exe(r"C:\Windows\System32\wuauserv.dll", MS)
    r = p.reg
    r.put("HKCU", RUN_HKCU, "OneDrive", r'"C:\Users\Demo\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background')
    r.put("HKCU", RUN_HKCU, "Spotify", r'"C:\Users\Demo\AppData\Roaming\Spotify\Spotify.exe" --minimized')
    r.put("HKCU", RUN_HKCU, "Discord", r'"C:\Users\Demo\AppData\Local\Discord\Update.exe" --processStart Discord.exe')
    r.put("HKCU", RUN_HKCU, "Steam", r'"C:\Program Files\Steam\steam.exe" -silent')
    r.put("HKCU", RUN_HKCU, "Northwind Sync", r'"C:\Users\Demo\AppData\Local\Programs\Northwind Sync\nwsync.exe" --tray')
    r.put("HKCU", RUN_HKCU, "UpdaterHelper", r"C:\Users\Demo\AppData\Local\Temp\updater_helper.exe /quiet")
    r.put("HKCU", AP + r"\Run", "Steam", make_approved_disabled())
    r.put("HKCU", AP + r"\Run", "Spotify", b"\x02" + b"\x00" * 11)
    r.put("HKLM", RUN_HKLM, "SecurityHealth", r"%windir%\system32\SecurityHealthSystray.exe", "expand_sz")
    r.put("HKLM", RUN_HKLM, "Acme Update", r'"C:\Program Files\Common Files\Acme\AcmeUpdate.exe" /check')
    r.put("HKLM", RUN_WOW, "FabAudio", r'"C:\Program Files\Fabrikam Audio\FabAudioMgr.exe" /tray')
    r.put("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "CorpAgent", r"C:\Corp\agent.exe")
    uf, cf = p.startup_folders()[0][1], p.startup_folders()[1][1]
    p.add_dirfile(uf, "desktop.ini", b"[.ShellClassInfo]")
    p.add_dirfile(uf, "Dropbox.lnk", build_lnk(P + r"\Dropbox\Client\Dropbox.exe", "/systemstartup"))
    p.add_dirfile(cf, "Contoso Backup Tray.lnk", build_lnk(P + r"\Contoso Backup\cbtray.exe", "--startup"))
    p.tasks = json.dumps([
        {"n": "NorthwindSyncUpdate", "p": "\\", "s": 3, "d": "Keeps Northwind Sync up to date.", "a": "Northwind Software Ltd", "u": r"DESKTOP\Demo", "rl": 0, "trg": [{"c": "MSFT_TaskLogonTrigger", "e": True}], "x": [{"e": r"C:\Users\Demo\AppData\Local\Programs\Northwind Sync\nwsync.exe", "g": "--update"}]},
        {"n": "ContosoBackupStartup", "p": "\\Contoso\\", "s": 3, "d": "", "a": "Contoso Ltd.", "u": "SYSTEM", "rl": 1, "trg": [{"c": "MSFT_TaskBootTrigger", "e": True}], "x": [{"e": r"C:\Program Files\Contoso Backup\cbservice.exe", "g": "/boot"}]},
        {"n": "Legacy Cleaner", "p": "\\", "s": 1, "d": "", "a": "", "u": r"DESKTOP\Demo", "rl": 0, "trg": [{"c": "MSFT_TaskLogonTrigger", "e": True}], "x": [{"e": r"C:\Users\Demo\AppData\Local\Temp\updater_helper.exe", "g": "/clean"}]},
        {"n": "Consolidator", "p": "\\Microsoft\\Windows\\Customer Experience Improvement Program\\", "s": 3, "d": "Windows telemetry", "a": "Microsoft", "u": "SYSTEM", "rl": 1, "trg": [{"c": "MSFT_TaskLogonTrigger", "e": True}], "x": [{"e": "%SystemRoot%\\System32\\wsqmcons.exe", "g": ""}]},
    ])
    add_service(p, "ContosoBackupSvc", image=r'"C:\Program Files\Contoso Backup\cbservice.exe" /service', display="Contoso Backup Service", delayed=True, desc="Runs scheduled backups.")
    add_service(p, "FabAudioSvc", image=r'"C:\Program Files\Fabrikam Audio\fabsvc.exe"', display="Fabrikam Audio Service")
    add_service(p, "Spooler", image=r"%SystemRoot%\System32\spoolsv.exe", display="@%systemroot%\\system32\\spoolsv.exe,-1")
    p.indirect["@%systemroot%\\system32\\spoolsv.exe,-1"] = "Print Spooler"
    add_service(p, "wuauserv", typ=0x20, image=r"%SystemRoot%\System32\svchost.exe -k netsvcs -p", display="Windows Update", dll=r"%SystemRoot%\System32\wuauserv.dll", trigger=True)
    add_service(p, "ManualThing", start=3, image=r"C:\Program Files\Contoso Backup\cbservice.exe", display="Manual thing")
    add_service(p, "SomeDriver", typ=1, start=2, image=r"\SystemRoot\System32\drivers\x.sys", display="A driver")
    p.perf = demo_perf_xml()
    return p

def make_approved_disabled():
    return b"\x03\x00\x00\x00" + struct.pack("<Q", 133_500_000_000_000_000)

def event_xml(eid, data, when=None):
    when = when or time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime(time.time() - 3 * 3600))
    d = "".join('<Data Name="%s">%s</Data>' % (k, v) for k, v in data.items())
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>%d</EventID><TimeCreated SystemTime="%s"/></System><EventData>%s</EventData></Event>' % (eid, when, d))

def demo_perf_xml():
    return "\n".join([
        event_xml(100, {"BootTime": 48230, "MainPathBootTime": 21000}),
        event_xml(101, {"Name": "OneDrive.exe", "FriendlyName": "Microsoft OneDrive", "TotalTime": 4120, "DegradationTime": 2100}),
        event_xml(101, {"Name": "Dropbox.exe", "FriendlyName": "Dropbox", "TotalTime": 1850, "DegradationTime": 700}),
        event_xml(101, {"Name": "Update.exe", "FriendlyName": "Discord", "TotalTime": 2600, "DegradationTime": 900}),
        event_xml(101, {"Name": "nwsync.exe", "FriendlyName": "Northwind Sync", "TotalTime": 650}),
        event_xml(103, {"Name": "ContosoBackupSvc", "FriendlyName": "Contoso Backup Service", "TotalTime": 3300}),
        event_xml(101, {"Name": "OneDrive.exe", "FriendlyName": "Microsoft OneDrive", "TotalTime": 2000}),
    ])
