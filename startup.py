"""StartupScope engine: finds everything that launches at Windows startup and toggles it reversibly.

All Windows access goes through a platform object (see winapi.WinPlatform; tests use a fake), so the logic
here (parsing, StartupApproved bytes, impact matching, backups, undo) runs and is tested on any OS.
Items are always identified by an opaque id made by this module; the browser never supplies a registry
path, task name or file path to act on."""
import base64
import hashlib
import json
import ntpath
import os
import re
import struct
import threading
import time
import xml.etree.ElementTree as ET

AP_BASE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
RUN_KEYS = [
    # hive, key path, label, StartupApproved hive, StartupApproved key
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", "HKCU", AP_BASE + r"\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", "HKLM", AP_BASE + r"\Run"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)", "HKLM", AP_BASE + r"\Run32"),
]
POLICY_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU Policy Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM Policy Run"),
]
SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
KIND_LABEL = {"run": "Run key", "folder": "Startup folder", "task": "Scheduled task", "service": "Service"}
ADMIN_MSG = "Needs administrator. Start StartupScope with “Run as administrator” to change this item."
WINDOWS_MSG = "Windows component: not changeable here."
POLICY_MSG = "Set by group policy or another program; not changeable here."
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.$ \-]{0,255}$")
EXEC_RE = re.compile(r"\.(exe|com|bat|cmd|scr|msc|cpl|lnk|ps1|vbs|js)$", re.I)


class ChangeError(Exception):
    def __init__(self, msg, needs_admin=False):
        super().__init__(msg)
        self.needs_admin = needs_admin


def make_id(kind, source, name):
    return hashlib.sha1(("%s|%s|%s" % (kind, source, name)).lower().encode("utf-8", "replace")).hexdigest()[:16]


# ------------------------------------------------------------------ StartupApproved bytes
def approved_enabled(data):
    """Task Manager: first byte 02/06 = enabled, 03/07 = disabled (low bit set). Missing = enabled."""
    if not data:
        return True
    return (data[0] & 1) == 0


def make_approved(enabled, now=None):
    if enabled:
        return b"\x02" + b"\x00" * 11
    ft = int((now if now is not None else time.time()) * 10_000_000) + 116444736000000000
    return b"\x03\x00\x00\x00" + struct.pack("<Q", ft)


# ------------------------------------------------------------------ command line + shortcut parsing
def split_command(cmd, exists):
    """Return (target_path, args) from a command line like '"C:\\a b\\x.exe" -min' or 'C:\\Program Files\\x\\y.exe /s'."""
    cmd = (cmd or "").strip()
    if not cmd:
        return "", ""
    if cmd[0] == '"':
        end = cmd.find('"', 1)
        if end > 0:
            return cmd[1:end], cmd[end + 1:].strip()
        return cmd[1:], ""
    parts = cmd.split(" ")
    for n in range(len(parts), 0, -1):          # longest prefix that exists on disk (unquoted paths with spaces)
        cand = " ".join(parts[:n])
        if (n == len(parts) or EXEC_RE.search(cand)) and exists(cand):
            return cand, " ".join(parts[n:]).strip()
    return parts[0], " ".join(parts[1:]).strip()


def parse_lnk(data, lnk_dir=""):
    """Minimal MS-SHLLINK reader: {'target','args','workdir'} (any may be ''). Never raises."""
    out = {"target": "", "args": "", "workdir": ""}
    try:
        if len(data) < 76 or struct.unpack_from("<I", data, 0)[0] != 0x4C:
            return out
        flags = struct.unpack_from("<I", data, 0x14)[0]
        pos = 76
        if flags & 1:                                    # HasLinkTargetIDList
            pos += 2 + struct.unpack_from("<H", data, pos)[0]
        target = ""
        if flags & 2:                                    # HasLinkInfo
            base = pos
            size, hdr, lflags, _vol, lbp, _cnr, cps = struct.unpack_from("<IIIIIII", data, base)
            if lflags & 1:
                if hdr >= 0x24:
                    lbp_u, cps_u = struct.unpack_from("<II", data, base + 0x1C)
                    a = data[base + lbp_u:].split(b"\x00\x00")[0]
                    b = data[base + cps_u:].split(b"\x00\x00")[0]
                    a += b"\x00" if len(a) % 2 else b""
                    b += b"\x00" if len(b) % 2 else b""
                    target = a.decode("utf-16-le", "replace") + b.decode("utf-16-le", "replace")
                else:
                    a = data[base + lbp:].split(b"\x00")[0].decode("mbcs" if os.name == "nt" else "latin-1", "replace")
                    b = data[base + cps:].split(b"\x00")[0].decode("mbcs" if os.name == "nt" else "latin-1", "replace")
                    target = a + b
            pos += size
        uni = bool(flags & 0x80)
        vals = {}
        for bit, key in ((4, "name"), (8, "rel"), (0x10, "workdir"), (0x20, "args"), (0x40, "icon")):
            if flags & bit:
                n = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                if uni:
                    vals[key] = data[pos:pos + 2 * n].decode("utf-16-le", "replace"); pos += 2 * n
                else:
                    vals[key] = data[pos:pos + n].decode("latin-1", "replace"); pos += n
        if not target and vals.get("rel") and lnk_dir:
            target = ntpath.normpath(ntpath.join(lnk_dir, vals["rel"]))
        out.update(target=target, args=vals.get("args", ""), workdir=vals.get("workdir", ""))
    except (struct.error, ValueError, IndexError):
        pass
    return out


# ------------------------------------------------------------------ Diagnostics-Performance events
def parse_perf_events(xml_text):
    """Event 100 = boot degradation (BootTime), 101 = app start slowed, 103 = service start slowed. Returns
    {'boot_ms': int|None, 'boot_time': epoch|None, 'apps': {lower name: ms}, 'services': {lower name: ms}}."""
    res = {"boot_ms": None, "boot_time": None, "apps": {}, "services": {}}
    if not xml_text or "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        return res
    try:
        root = ET.fromstring("<Events>" + re.sub(r"<\?xml[^>]*\?>", "", xml_text) + "</Events>")
    except ET.ParseError:
        return res
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    for ev in root.iter(ns + "Event"):
        try:
            eid = int((ev.findtext(ns + "System/" + ns + "EventID") or "0").strip())
        except ValueError:
            continue
        data = {d.get("Name"): (d.text or "") for d in ev.iter(ns + "Data") if d.get("Name")}

        def ms(key):
            try:
                return int(float(data.get(key, "")))
            except ValueError:
                return None
        if eid == 100 and res["boot_ms"] is None:
            res["boot_ms"] = ms("BootTime")
            tc = ev.find(ns + "System/" + ns + "TimeCreated")
            if tc is not None and tc.get("SystemTime"):
                try:
                    res["boot_time"] = time.mktime(time.strptime(tc.get("SystemTime")[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
                except ValueError:
                    pass
        elif eid in (101, 103):
            total = ms("TotalTime")
            if total is None:
                continue
            bucket = res["apps"] if eid == 101 else res["services"]
            for key in ("Name", "FriendlyName"):
                nm = (data.get(key) or "").strip().lower()
                if nm:
                    bucket[nm] = max(bucket.get(nm, 0), total)
    return res


def impact_label(ms):
    if ms is None:
        return "n/a"
    return "High" if ms >= 3000 else "Medium" if ms >= 1000 else "Low"


# ------------------------------------------------------------------ the scanner
class Scanner:
    def __init__(self, plat, store):
        self.p = plat
        self.store = store
        self.items = []
        self.by_id = {}
        self.lock = threading.RLock()
        self.sig_cache = store.sig_cache() if store else {}
        self.state = {"scanning": False, "last_scan": None, "errors": [], "impact_ok": False, "impact_note": "", "boot_ms": None, "boot_time": None, "verified": 0, "to_verify": 0}
        self._scan_lock = threading.Lock()
        self._verify_gen = 0

    # ---- enumeration
    def _resolve(self, path):
        """Bare names like 'cmd.exe' or 'rundll32' are found the way Windows would (System32, then PATH)."""
        if path and not ntpath.dirname(path):
            return self.p.which(path) or path
        return path

    def _item(self, kind, source, location, name, command, enabled, **kw):
        target, args = split_command(self.p.expand(command), self.p.exists)
        target = self._resolve(target)
        it = {"id": make_id(kind, source, name if kind != "folder" else location + "|" + name), "kind": kind, "type": KIND_LABEL[kind], "source": source, "location": location,
              "name": name, "display": kw.pop("display", None) or name, "command": command, "target": kw.pop("target", None) or target, "args": args, "enabled": enabled,
              "can_toggle": False, "needs_admin": False, "protected": False, "reason": "", "desc": "", "impact_ms": None, "impact": "n/a",
              "publisher": "", "sig": "pending", "sig_detail": "", "extra": {}}
        it.update(kw)
        return it

    def _run_items(self):
        out = []
        admin = self.p.is_admin()
        for hive, key, label, ah, ak in RUN_KEYS:
            try:
                vals = self.p.reg.values(hive, key)
            except PermissionError:
                self.state["errors"].append("Could not read %s %s (access denied)" % (hive, key)); continue
            for name, (data, typ) in vals.items():
                if typ not in ("sz", "expand_sz") or not isinstance(data, str):
                    continue
                ap = self.p.reg.get(ah, ak, name)
                enabled = approved_enabled(ap[0] if ap and isinstance(ap[0], (bytes, bytearray)) else None)
                it = self._item("run", label, "%s\\%s" % (hive, key), name or "(Default)", data, enabled)
                it["_ref"] = {"approved": [ah, ak, name]}
                self._perm(it, hive == "HKLM", admin)
                out.append(it)
        for hive, key, label in POLICY_KEYS:
            try:
                vals = self.p.reg.values(hive, key)
            except PermissionError:
                continue
            for name, (data, typ) in vals.items():
                if typ in ("sz", "expand_sz") and isinstance(data, str):
                    it = self._item("run", label, "%s\\%s" % (hive, key), name, data, True)
                    it.update(can_toggle=False, reason=POLICY_MSG)
                    out.append(it)
        return out

    def _perm(self, it, hklm, admin):
        if hklm:
            it["needs_admin"] = True
            it["can_toggle"] = bool(admin)
            it["reason"] = "" if admin else ADMIN_MSG
        else:
            it["can_toggle"] = True

    def _folder_items(self):
        out = []
        admin = self.p.is_admin()
        for hive, folder, label in self.p.startup_folders():
            try:
                names = self.p.list_dir(folder)
            except OSError:
                continue
            for fn in sorted(names, key=str.lower):
                if fn.lower() == "desktop.ini":
                    continue
                full = ntpath.join(folder, fn)
                if self.p.isdir(full):
                    continue
                ap = self.p.reg.get(hive, AP_BASE + r"\StartupFolder", fn)
                enabled = approved_enabled(ap[0] if ap and isinstance(ap[0], (bytes, bytearray)) else None)
                target, args = full, ""
                if fn.lower().endswith(".lnk"):
                    try:
                        info = parse_lnk(self.p.read_file(full, 65536), folder)
                    except OSError:
                        info = {"target": "", "args": "", "workdir": ""}
                    if info["target"]:
                        target, args = info["target"], info["args"]
                cmd = ('"%s" %s' % (target, args)).strip() if target != full else full
                it = self._item("folder", label, folder, fn, cmd, enabled, display=ntpath.splitext(fn)[0], target=target)
                it["args"] = args
                it["_ref"] = {"approved": [hive, AP_BASE + r"\StartupFolder", fn]}
                self._perm(it, hive == "HKLM", admin)
                out.append(it)
        return out

    def _task_items(self):
        out = []
        admin = self.p.is_admin()
        me = self.p.current_user().lower()
        raw = self.p.tasks_json()
        if not raw or not raw.strip():
            return out
        try:
            data = json.loads(raw)
        except ValueError:
            self.state["errors"].append("Scheduled task list was not readable"); return out
        if isinstance(data, dict):
            data = [data]
        for t in data if isinstance(data, list) else []:
            if not isinstance(t, dict):
                continue
            tpath = str(t.get("p") or "\\")
            tname = str(t.get("n") or "")
            if not tname:
                continue
            full = tpath + tname
            trig = t.get("trg") or []
            trig = [trig] if isinstance(trig, (str, dict)) else trig
            kinds = []
            for x in trig:
                cls = str(x.get("c") if isinstance(x, dict) else x)
                lab = "At log on" if "Logon" in cls else "At startup" if "Boot" in cls else None
                if lab and lab not in kinds:
                    kinds.append(lab)
            if not kinds:
                continue
            acts = t.get("x") or []
            acts = [acts] if isinstance(acts, dict) else acts
            first = next((a for a in acts if isinstance(a, dict) and a.get("e")), None)
            cmd = ""
            if first:
                cmd = ('"%s" %s' % (first.get("e"), first.get("g") or "")).strip() if " " in str(first.get("e")) else ("%s %s" % (first.get("e"), first.get("g") or "")).strip()
            state = t.get("s")
            enabled = state != 1
            user = str(t.get("u") or "")
            owned = bool(user) and (user.lower() == me or user.lower().split("\\")[-1] == me.split("\\")[-1]) and int(t.get("rl") or 0) == 0
            it = self._item("task", "Scheduled task", tpath, full, cmd, enabled, display=tname)
            it["desc"] = str(t.get("d") or "")[:300]
            it["extra"] = {"triggers": kinds, "runs_as": user, "author": str(t.get("a") or ""), "actions": len(acts), "elevated": int(t.get("rl") or 0) == 1}
            it["_ref"] = {"task": full}
            if tpath.lower().startswith("\\microsoft\\windows\\"):
                it.update(protected=True, reason=WINDOWS_MSG)
            else:
                it["needs_admin"] = not owned
                it["can_toggle"] = bool(owned or admin)
                it["reason"] = "" if it["can_toggle"] else ADMIN_MSG
            out.append(it)
        return out

    def _service_items(self):
        out = []
        admin = self.p.is_admin()
        win = (self.p.windir() or "").lower().rstrip("\\/")
        try:
            names = self.p.reg.subkeys("HKLM", SERVICES_KEY)
        except PermissionError:
            self.state["errors"].append("Could not read services (access denied)"); return out
        ours = self._services_we_disabled()
        for sn in names:
            try:
                v = self.p.reg.values("HKLM", SERVICES_KEY + "\\" + sn)
            except PermissionError:
                continue
            def g(key, d=None):
                x = v.get(key)
                return x[0] if x else d
            start, typ = g("Start"), g("Type")
            if not isinstance(start, int) or not isinstance(typ, int) or not (typ & 0x30) or (typ & 0x0B):
                continue
            was_disabled_by_us = start == 3 and sn in ours      # keep it listed so it can be switched back on
            if start != 2 and not was_disabled_by_us:
                continue
            image = g("ImagePath", "") if isinstance(g("ImagePath", ""), str) else ""
            delayed = (g("DelayedAutostart") == 1) if not was_disabled_by_us else bool(ours[sn])
            trigger = "TriggerInfo" in self.p.reg.subkeys("HKLM", SERVICES_KEY + "\\" + sn)
            cmd = self.p.expand(image)
            target, args = split_command(cmd, self.p.exists)
            if ntpath.basename(target).lower() == "svchost.exe":
                p = self.p.reg.get("HKLM", SERVICES_KEY + "\\" + sn + r"\Parameters", "ServiceDll")
                if p and isinstance(p[0], str):
                    target = self.p.expand(p[0])
            disp = g("DisplayName", sn)
            disp = self.p.indirect_string(disp) if isinstance(disp, str) and disp.startswith("@") else disp
            desc = g("Description", "")
            desc = self.p.indirect_string(desc) if isinstance(desc, str) and desc.startswith("@") else desc
            it = self._item("service", "Service", "Services\\" + sn, sn, cmd, not was_disabled_by_us, display=disp or sn, target=target)
            it["args"] = args
            it["desc"] = str(desc or "")[:300]
            it["extra"] = {"start": "Manual (disabled by StartupScope)" if was_disabled_by_us else "Automatic (delayed)" if delayed else "Automatic (trigger start)" if trigger else "Automatic", "account": str(g("ObjectName", "") or ""), "delayed": delayed}
            it["_ref"] = {"service": sn, "delayed": delayed}
            if win and target.lower().startswith(win + "\\"):
                it.update(protected=True, reason=WINDOWS_MSG)
            else:
                it["needs_admin"] = True
                it["can_toggle"] = bool(admin and SERVICE_NAME_RE.match(sn))
                it["reason"] = "" if it["can_toggle"] else ADMIN_MSG
            out.append(it)
        return out

    def _services_we_disabled(self):
        """{service name: was delayed} for services whose latest recorded change is a disable that was not undone."""
        state = {}
        for c in (self.store.changes() if self.store else []):
            if isinstance(c, dict) and c.get("kind") == "service" and not c.get("undone") and (c.get("undo") or {}).get("service"):
                sn = c["undo"]["service"]
                if c.get("action") == "disable":
                    state[sn] = c.get("delayed", False)
                else:
                    state.pop(sn, None)
        return state

    def scan(self):
        if not self._scan_lock.acquire(blocking=False):
            return False
        try:
            self.state.update(scanning=True, errors=[])
            items = []
            for fn in (self._run_items, self._folder_items, self._task_items, self._service_items):
                try:
                    items += fn()
                except Exception as e:  # noqa: BLE001  one bad source must not hide the others
                    self.state["errors"].append("%s failed: %s" % (fn.__name__.strip("_").replace("_items", ""), e))
            self._apply_impact(items)
            for it in items:
                it["publisher"] = ""
                c = self.sig_cache.get(self._sig_key(it["target"]))
                it["sig"] = "pending"
                if c:
                    self._set_sig(it, c)
            with self.lock:
                self.items = items
                self.by_id = {i["id"]: i for i in items}
            if self.store:
                self.store.snapshot(items)
            self.state.update(last_scan=time.time())
            return True
        finally:
            self.state["scanning"] = False
            self._scan_lock.release()

    def _apply_impact(self, items):
        out = self.p.perf_events_xml()
        if out is None:
            self.state.update(impact_ok=False, impact_note="n/a: the Windows boot-performance log could not be read without administrator rights.", boot_ms=None, boot_time=None)
            return
        ev = parse_perf_events(out)
        self.state.update(impact_ok=True, boot_ms=ev["boot_ms"], boot_time=ev["boot_time"],
                          impact_note="Windows only logs startup slowdowns, so n/a means it was not flagged as slow." if (ev["apps"] or ev["services"]) else
                          "The log is readable, but Windows has not recorded any slow startup items recently.")
        for it in items:
            exe = ntpath.basename(it["target"] or "").lower()
            keys = [it["name"].lower(), it["display"].lower()]
            if exe:
                keys.append(exe)
            pool = ev["services"] if it["kind"] == "service" else ev["apps"]
            ms = max([pool[k] for k in keys if k in pool] or [0]) or None
            it["impact_ms"] = ms
            it["impact"] = impact_label(ms)

    # ---- signatures (background)
    def _sig_key(self, path):
        st = self.p.stat(path) if path else None
        return "%s|%s|%s" % ((path or "").lower(), st[0], int(st[1])) if st else "%s|missing" % (path or "").lower()

    def _set_sig(self, it, c):
        it["sig"] = c.get("state", "unknown")
        it["publisher"] = c.get("publisher") or c.get("company") or ""
        it["sig_detail"] = c.get("detail", "")

    def verify_all(self, stop=None):
        with self.lock:
            self._verify_gen += 1
            gen = self._verify_gen
            todo = [i for i in self.items if i["sig"] == "pending"]
        self.state.update(to_verify=len(todo), verified=0)
        dirty = False
        for n, it in enumerate(todo):
            if (stop and stop.is_set()) or gen != self._verify_gen:
                break
            path = it["target"]
            key = self._sig_key(path)
            c = self.sig_cache.get(key)
            if c is None:
                try:
                    c = self.p.sig(path) if path and self.p.exists(path) else {"state": "missing", "publisher": "", "detail": "File not found"}
                except Exception as e:  # noqa: BLE001
                    c = {"state": "unknown", "publisher": "", "detail": str(e)[:100]}
                self.sig_cache[key] = c
                dirty = True
                time.sleep(0.005)
            self._set_sig(it, c)
            self.state["verified"] = n + 1
        if dirty and self.store:
            self.store.save_sig_cache(self.sig_cache)
        self.state.update(to_verify=0)

    # ---- views
    def public(self, it):
        return {k: v for k, v in it.items() if not k.startswith("_")}

    def listing(self):
        with self.lock:
            return [self.public(i) for i in self.items]

    # ---- changing things
    def toggle(self, item_id, enable):
        with self.lock:
            it = self.by_id.get(item_id)
        if it is None:
            raise KeyError("That item is no longer in the list. Refresh and try again.")
        if it["enabled"] == enable:
            return it, None
        if it["protected"] or not it["can_toggle"]:
            raise ChangeError(it["reason"] or ADMIN_MSG, needs_admin=it["needs_admin"] and not self.p.is_admin() and not it["protected"])
        ref = it["_ref"]
        rec = {"item_id": it["id"], "item": it["name"], "display": it["display"], "kind": it["kind"], "source": it["source"], "location": it["location"], "command": it["command"], "action": "enable" if enable else "disable"}
        if "approved" in ref:
            hive, key, name = ref["approved"]
            prev = self.p.reg.get(hive, key, name)
            prev_hex = prev[0].hex() if prev and isinstance(prev[0], (bytes, bytearray)) else None
            new = make_approved(enable)
            try:
                self.p.reg.set_binary(hive, key, name, new)
            except PermissionError:
                raise ChangeError(ADMIN_MSG, needs_admin=True) from None
            rec["undo"] = {"type": "approved", "hive": hive, "key": key, "name": name, "prev_hex": prev_hex}
            rec["backup"] = {"hive": hive, "key": key, "value": name, "before_hex": prev_hex, "after_hex": new.hex()}
            actual = self.p.reg.get(hive, key, name)
            it["enabled"] = approved_enabled(actual[0] if actual else None)
        elif "task" in ref:
            rc, text = self.p.run(["schtasks.exe", "/change", "/tn", ref["task"], "/enable" if enable else "/disable"])
            if rc != 0:
                denied = rc == 1 or "denied" in (text or "").lower() or "access" in (text or "").lower()
                raise ChangeError((ADMIN_MSG if denied else "Windows could not change this task.") + (" (" + (text or "").strip()[:160] + ")" if text and text.strip() else ""), needs_admin=denied)
            rec["undo"] = {"type": "task", "task": ref["task"], "was_enabled": it["enabled"]}
            rec["backup"] = {"task": ref["task"], "was_enabled": it["enabled"]}
            it["enabled"] = enable
        elif "service" in ref:
            sn = ref["service"]
            if not SERVICE_NAME_RE.match(sn):
                raise ChangeError("This service name cannot be changed from here.")
            mode = "auto" if not ref.get("delayed") else "delayed-auto"
            rc, text = self.p.run(["sc.exe", "config", sn, "start=", mode if enable else "demand"])
            if rc != 0:
                denied = rc == 5 or "denied" in (text or "").lower()
                raise ChangeError(ADMIN_MSG if denied else "Windows could not change this service.", needs_admin=denied)
            rec["delayed"] = bool(ref.get("delayed"))
            rec["undo"] = {"type": "service", "service": sn, "mode": "demand" if enable else mode}
            rec["backup"] = {"service": sn, "start_before": "Automatic" + (" (delayed)" if ref.get("delayed") else ""), "start_after": "Manual" if not enable else "Automatic"}
            it["enabled"] = enable
        else:
            raise ChangeError("This item cannot be changed.")
        rec = self.store.add_change(rec) if self.store else rec
        return it, rec

    def undo(self, change_id):
        c = self.store.get_change(change_id) if self.store else None
        if not c or c.get("undone"):
            raise KeyError("That change was not found or was already undone.")
        u = c.get("undo") or {}
        t = u.get("type")
        if t == "approved":
            try:
                if u.get("prev_hex") is None:
                    self.p.reg.delete_value(u["hive"], u["key"], u["name"])
                else:
                    self.p.reg.set_binary(u["hive"], u["key"], u["name"], bytes.fromhex(u["prev_hex"]))
            except PermissionError:
                raise ChangeError(ADMIN_MSG, needs_admin=True) from None
        elif t == "task":
            rc, text = self.p.run(["schtasks.exe", "/change", "/tn", u["task"], "/enable" if u.get("was_enabled") else "/disable"])
            if rc != 0:
                raise ChangeError("Windows could not undo this change." + (" (" + text.strip()[:160] + ")" if text and text.strip() else ""), needs_admin="denied" in (text or "").lower())
        elif t == "service":
            if not SERVICE_NAME_RE.match(u.get("service", "")):
                raise ChangeError("This service name cannot be changed from here.")
            rc, text = self.p.run(["sc.exe", "config", u["service"], "start=", u["mode"]])
            if rc != 0:
                raise ChangeError(ADMIN_MSG, needs_admin=True)
        else:
            raise ChangeError("This change cannot be undone automatically. The backup file lists the original value.")
        self.store.mark_undone(change_id)
        with self.lock:
            it = self.by_id.get(c.get("item_id"))
            if it is not None:
                if t == "approved":
                    it["enabled"] = approved_enabled(bytes.fromhex(u["prev_hex"]) if u.get("prev_hex") else None)
                elif t == "task":
                    it["enabled"] = bool(u.get("was_enabled"))
                elif t == "service":
                    it["enabled"] = u.get("mode") != "demand"
        return c
