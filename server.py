"""StartupScope routes. It lists and toggles startup items by opaque item id only; the browser never sends a
registry path, task name, service name or file path. Disabling is always reversible and backed up first."""
import csv
import io
import logging
import os
import threading
import time

import appserver
import startup
import storage
from appserver import BadRequest, NotFound

kit = appserver.Kit("StartupScope", "STARTUPSCOPE_PORT", 8772)
HOST, PORT = appserver.HOST, kit.port
last_seen = kit.last_seen
build_server = kit.build_server
VERSION = "1.0.0"
log = logging.getLogger("startupscope.server")
quit_event = threading.Event()
STOP = threading.Event()
WAKE = threading.Event()
SC = None
STORE = None
PLAT = None
_thread = None


class NullPlatform:
    """Non-Windows fallback (the box's launcher smoke test): nothing to list."""
    class reg:
        values = staticmethod(lambda h, p: {})
        get = staticmethod(lambda h, p, n: None)
        subkeys = staticmethod(lambda h, p: [])
    is_admin = staticmethod(lambda: False)
    current_user = staticmethod(lambda: "")
    windir = staticmethod(lambda: "")
    expand = staticmethod(lambda s: s)
    exists = staticmethod(lambda p: False)
    isdir = staticmethod(lambda p: False)
    which = staticmethod(lambda n: None)
    stat = staticmethod(lambda p: None)
    list_dir = staticmethod(lambda p: [])
    read_file = staticmethod(lambda p, n: b"")
    startup_folders = staticmethod(lambda: [])
    tasks_json = staticmethod(lambda: "")
    perf_events_xml = staticmethod(lambda: None)
    indirect_string = staticmethod(lambda s: "")
    run = staticmethod(lambda a, timeout=60: (1, "not supported on this system"))
    reveal = staticmethod(lambda p: None)
    sig = staticmethod(lambda p: {"state": "unknown", "publisher": "", "detail": ""})


def init(plat=None, store=None):
    global SC, STORE, PLAT
    STORE = store or storage.Store()
    if plat is None:
        if os.name == "nt":
            import winapi
            plat = winapi.WinPlatform()
        else:
            plat = NullPlatform()
    PLAT = plat
    SC = startup.Scanner(plat, STORE)


def _worker():
    while not STOP.is_set():
        WAKE.wait(timeout=900)          # also refresh every 15 minutes while open
        if STOP.is_set():
            break
        WAKE.clear()
        try:
            SC.scan()
            SC.verify_all(STOP)
        except Exception:  # noqa: BLE001
            log.exception("scan failed")


def on_start():
    global _thread
    if SC is None:
        init()
    if os.name == "nt":
        import winapi
        winapi.set_process_below_normal()
    STOP.clear()
    WAKE.set()
    _thread = threading.Thread(target=_worker, name="scan", daemon=True)
    _thread.start()


def on_stop():
    STOP.set()
    WAKE.set()


@kit.get("/api/status")
def status(_q):
    items = SC.listing()
    st = SC.state
    counts = {}
    for it in items:
        counts[it["kind"]] = counts.get(it["kind"], 0) + 1
    return {"version": VERSION, "admin": bool(PLAT.is_admin()), "windows": os.name == "nt" or bool(getattr(PLAT, "fake_windows", False)),
            "scanning": st["scanning"] or not st["last_scan"], "last_scan": st["last_scan"], "errors": st["errors"][:20],
            "verifying": st["to_verify"] > 0, "verified": st["verified"], "to_verify": st["to_verify"],
            "impact": {"ok": st["impact_ok"], "note": st["impact_note"], "boot_ms": st["boot_ms"], "boot_time": st["boot_time"]},
            "counts": counts, "total": len(items), "enabled": sum(1 for i in items if i["enabled"]),
            "unsigned": sum(1 for i in items if i["sig"] in ("unsigned", "invalid")),
            "data_dir": STORE.dir, "backup_dir": STORE.backups}


@kit.get("/api/items")
def items(_q):
    return {"items": SC.listing(), "last_scan": SC.state["last_scan"]}


@kit.post("/api/refresh")
def refresh(_b):
    WAKE.set()
    return {"ok": True}


def _item_id(body):
    i = body.get("id")
    if not isinstance(i, str) or not i or len(i) > 64:
        raise BadRequest("id is required")
    return i


@kit.post("/api/toggle")
def toggle(body):
    iid = _item_id(body)
    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        raise BadRequest("enabled must be true or false")
    with SC.lock:
        it = SC.by_id.get(iid)
    if it is None:
        raise NotFound("That item is no longer in the list. Refresh and try again.")
    if it["kind"] == "service" and body.get("confirm") is not True and it["enabled"] != enabled and it["can_toggle"]:
        return {"ok": False, "confirm": "service", "error": "Confirmation needed"}
    try:
        item, change = SC.toggle(iid, enabled)
    except startup.ChangeError as e:
        return {"ok": False, "error": str(e), "needs_admin": e.needs_admin}
    except KeyError as e:
        raise NotFound(str(e.args[0])) from None
    return {"ok": True, "item": SC.public(item), "change": change}


@kit.post("/api/undo")
def undo(body):
    cid = body.get("change_id")
    if not isinstance(cid, int) or isinstance(cid, bool):
        raise BadRequest("change_id is required")
    try:
        SC.undo(cid)
    except startup.ChangeError as e:
        return {"ok": False, "error": str(e), "needs_admin": e.needs_admin}
    except KeyError as e:
        raise NotFound(str(e.args[0])) from None
    WAKE.set()
    return {"ok": True}


@kit.get("/api/changes")
def changes(_q):
    out = []
    for c in reversed(STORE.changes()):
        if isinstance(c, dict):
            out.append({k: c.get(k) for k in ("id", "time", "item", "display", "kind", "source", "location", "action", "undone", "command")})
    return {"changes": out[:100], "backup_dir": STORE.backups}


@kit.post("/api/reveal")
def reveal(body):
    iid = _item_id(body)
    with SC.lock:
        it = SC.by_id.get(iid)
    if it is None:
        raise NotFound("That item is no longer in the list.")
    path = it.get("target") or ""
    if not path or not PLAT.exists(path):
        return {"ok": False, "error": "The file for this item was not found."}
    PLAT.reveal(path)
    return {"ok": True}


def _csv_safe(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@kit.raw("/api/export.csv")
def export_csv(_q):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Name", "Type", "Source", "Enabled", "Publisher", "Signature", "Boot impact (ms)", "Command", "Location"])
    for it in SC.listing():
        w.writerow([_csv_safe(it["display"]), it["type"], _csv_safe(it["source"]), "yes" if it["enabled"] else "no", _csv_safe(it["publisher"]), it["sig"],
                    it["impact_ms"] if it["impact_ms"] is not None else "n/a", _csv_safe(it["command"]), _csv_safe(it["location"])])
    body = ("\ufeff" + buf.getvalue()).encode("utf-8")
    name = "startupscope-%s.csv" % time.strftime("%Y%m%d-%H%M")
    return 200, body, "text/csv; charset=utf-8", {"Content-Disposition": 'attachment; filename="%s"' % name}


@kit.post("/api/quit")
def quit_app(_b):
    quit_event.set()
    return {"ok": True}
