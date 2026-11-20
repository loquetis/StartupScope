"""StartupScope data folder (%APPDATA%\\StartupScope): change log, per-change backups, signature cache, settings."""
import json
import os
import threading
import time

APP = "StartupScope"
DATA_DIR = os.environ.get("STARTUPSCOPE_DATA") or os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~/.local/share"), APP)
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
MAX_CHANGES = 300
_lock = threading.Lock()


def _atomic_write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


class Store:
    """Changes are kept in changes.json (newest last). Every change also gets its own backup file with the
    complete before-state so it can be restored by hand even if this app is gone."""

    def __init__(self, data_dir=None):
        self.dir = data_dir or DATA_DIR
        self.backups = os.path.join(self.dir, "backups")
        self.changes_path = os.path.join(self.dir, "changes.json")
        os.makedirs(self.backups, exist_ok=True)

    def changes(self):
        with _lock:
            data = _read_json(self.changes_path, [])
        return data if isinstance(data, list) else []

    def add_change(self, rec):
        with _lock:
            data = _read_json(self.changes_path, [])
            if not isinstance(data, list):
                data = []
            rec = dict(rec)
            rec["id"] = (max([c.get("id", 0) for c in data if isinstance(c, dict)] or [0]) + 1)
            rec["time"] = time.time()
            rec["undone"] = False
            data.append(rec)
            data = data[-MAX_CHANGES:]
            _atomic_write(self.changes_path, json.dumps(data, indent=1))
            stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(rec["time"]))
            _atomic_write(os.path.join(self.backups, "%s-change%d.json" % (stamp, rec["id"])), json.dumps(rec, indent=1))
        return rec

    def get_change(self, cid):
        for c in self.changes():
            if isinstance(c, dict) and c.get("id") == cid:
                return c
        return None

    def mark_undone(self, cid):
        with _lock:
            data = _read_json(self.changes_path, [])
            for c in data:
                if isinstance(c, dict) and c.get("id") == cid:
                    c["undone"] = True
            _atomic_write(self.changes_path, json.dumps(data, indent=1))

    def snapshot(self, items):
        """Full list of what was found, written the first time we ever run (so there is always a 'before')."""
        path = os.path.join(self.backups, "initial-snapshot.json")
        if os.path.exists(path):
            return path
        slim = [{k: it.get(k) for k in ("kind", "source", "location", "name", "command", "enabled")} for it in items]
        _atomic_write(path, json.dumps({"time": time.time(), "items": slim}, indent=1))
        return path

    def sig_cache(self):
        d = _read_json(os.path.join(self.dir, "sigcache.json"), {})
        return d if isinstance(d, dict) else {}

    def save_sig_cache(self, d):
        if len(d) > 5000:
            d = dict(list(d.items())[-4000:])
        _atomic_write(os.path.join(self.dir, "sigcache.json"), json.dumps(d))
