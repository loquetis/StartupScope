"""Windows-only access for StartupScope: registry (winreg), signatures (WinVerifyTrust), process helpers.
Nothing here needs administrator rights to *read*. Imported lazily, so the rest of the app runs on any OS."""
import base64
import ctypes
import os
import subprocess
import sys

NO_WINDOW = 0x08000000
TASKS_PS = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$r=@(Get-ScheduledTask | ForEach-Object {
  $t=$_
  $trg=@($t.Triggers | ForEach-Object { @{c=[string]$_.CimClass.CimClassName; e=[bool]$_.Enabled} } | Where-Object { $_.c -match 'Logon|Boot' })
  if ($trg.Count -gt 0) {
    @{ n=[string]$t.TaskName; p=[string]$t.TaskPath; s=[int]$t.State; d=[string]$t.Description; a=[string]$t.Author;
       u=[string]$t.Principal.UserId; rl=[int]$t.Principal.RunLevel; trg=$trg;
       x=@($t.Actions | ForEach-Object { @{e=[string]$_.Execute; g=[string]$_.Arguments} }) }
  }
})
ConvertTo-Json -InputObject $r -Compress -Depth 5
"""


class WinReg:
    def __init__(self):
        import winreg
        self.w = winreg
        self.hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        self.types = {winreg.REG_SZ: "sz", winreg.REG_EXPAND_SZ: "expand_sz", winreg.REG_DWORD: "dword", winreg.REG_BINARY: "binary"}

    def _open(self, hive, path, write=False):
        w = self.w
        return w.OpenKey(self.hives[hive], path, 0, (w.KEY_SET_VALUE if write else w.KEY_READ) | w.KEY_WOW64_64KEY)

    def values(self, hive, path):
        out = {}
        try:
            k = self._open(hive, path)
        except FileNotFoundError:
            return out
        except PermissionError:
            raise
        except OSError:
            return out
        try:
            i = 0
            while True:
                try:
                    name, data, typ = self.w.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                out[name or "(Default)"] = (bytes(data) if isinstance(data, (bytes, bytearray)) else data, self.types.get(typ, "other"))
        finally:
            self.w.CloseKey(k)
        return out

    def get(self, hive, path, name):
        try:
            k = self._open(hive, path)
        except OSError:
            return None
        try:
            data, typ = self.w.QueryValueEx(k, name)
            return (bytes(data) if isinstance(data, (bytes, bytearray)) else data, self.types.get(typ, "other"))
        except OSError:
            return None
        finally:
            self.w.CloseKey(k)

    def subkeys(self, hive, path):
        out = []
        try:
            k = self._open(hive, path)
        except PermissionError:
            raise
        except OSError:
            return out
        try:
            i = 0
            while True:
                try:
                    out.append(self.w.EnumKey(k, i))
                except OSError:
                    break
                i += 1
        finally:
            self.w.CloseKey(k)
        return out

    def set_binary(self, hive, path, name, data):
        w = self.w
        try:
            k = w.CreateKeyEx(self.hives[hive], path, 0, w.KEY_SET_VALUE | w.KEY_WOW64_64KEY)
        except PermissionError:
            raise
        try:
            w.SetValueEx(k, name, 0, w.REG_BINARY, bytes(data))
        finally:
            w.CloseKey(k)

    def delete_value(self, hive, path, name):
        try:
            k = self._open(hive, path, write=True)
        except FileNotFoundError:
            return
        try:
            self.w.DeleteValue(k, name)
        except FileNotFoundError:
            pass
        finally:
            self.w.CloseKey(k)


class WinPlatform:
    def __init__(self):
        self.reg = WinReg()
        self._admin = None

    # ---- environment
    def is_admin(self):
        if self._admin is None:
            try:
                self._admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:  # noqa: BLE001
                self._admin = False
        return self._admin

    def current_user(self):
        return (os.environ.get("USERDOMAIN", "") + "\\" + os.environ.get("USERNAME", "")).strip("\\")

    def windir(self):
        return os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"

    def expand(self, s):
        return os.path.expandvars(s or "")

    def exists(self, p):
        try:
            return os.path.isfile(p)
        except (OSError, ValueError):
            return False

    def isdir(self, p):
        return os.path.isdir(p)

    def which(self, name):
        dirs = [os.path.join(self.windir(), "System32"), self.windir()] + [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]
        for d in dirs:
            for cand in (name, name + ".exe"):
                full = os.path.join(d, cand)
                if os.path.isfile(full):
                    return full
        return None

    def stat(self, p):
        try:
            st = os.stat(p)
            return (st.st_size, st.st_mtime)
        except (OSError, ValueError):
            return None

    def list_dir(self, p):
        return os.listdir(p)

    def read_file(self, p, limit):
        with open(p, "rb") as f:
            return f.read(limit)

    def startup_folders(self):
        out = []
        ad, pd = os.environ.get("APPDATA"), os.environ.get("ProgramData")
        if ad:
            out.append(("HKCU", os.path.join(ad, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), "Startup folder (you)"))
        if pd:
            out.append(("HKLM", os.path.join(pd, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), "Startup folder (all users)"))
        return out

    # ---- processes
    def run(self, args, timeout=60):
        try:
            r = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=NO_WINDOW, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as e:
            return 1, str(e)
        txt = (r.stdout or b"") + (r.stderr or b"")
        try:
            return r.returncode, txt.decode("mbcs", "replace")
        except LookupError:
            return r.returncode, txt.decode("utf-8", "replace")

    def tasks_json(self):
        ps = os.path.join(self.windir(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        enc = base64.b64encode(TASKS_PS.encode("utf-16-le")).decode("ascii")
        try:
            r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc],
                               capture_output=True, timeout=90, creationflags=NO_WINDOW, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return r.stdout.decode("utf-8", "replace").lstrip("\ufeff")

    def perf_events_xml(self):
        rc, out = self._wevt()
        return out if rc == 0 else None

    def _wevt(self):
        exe = os.path.join(self.windir(), "System32", "wevtutil.exe")
        try:
            r = subprocess.run([exe, "qe", "Microsoft-Windows-Diagnostics-Performance/Operational", "/q:*[System[(EventID=100 or EventID=101 or EventID=103)]]",
                                "/c:300", "/rd:true", "/f:xml"], capture_output=True, timeout=40, creationflags=NO_WINDOW, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return 1, ""
        return r.returncode, r.stdout.decode("utf-8", "replace")

    def reveal(self, path):
        subprocess.Popen(["explorer.exe", "/select," + path], creationflags=NO_WINDOW)

    def indirect_string(self, s):
        try:
            buf = ctypes.create_unicode_buffer(512)
            if ctypes.windll.shlwapi.SHLoadIndirectString(s, buf, 512, None) == 0 and buf.value:
                return buf.value
        except Exception:  # noqa: BLE001
            pass
        return ""

    # ---- signatures
    def sig(self, path):
        return check_signature(path)


def set_process_below_normal():
    try:
        k = ctypes.windll.kernel32
        k.SetPriorityClass(k.GetCurrentProcess(), 0x00004000)
    except Exception:  # noqa: BLE001
        pass


def company_name(path):
    """CompanyName from the file's version resource ('' if none)."""
    try:
        from ctypes import wintypes
        v = ctypes.windll.version
        v.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        v.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        v.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
        v.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
        size = v.GetFileVersionInfoSizeW(path, None)
        if not size:
            return ""
        buf = ctypes.create_string_buffer(size)
        if not v.GetFileVersionInfoW(path, 0, size, buf):
            return ""
        ptr, ln = ctypes.c_void_p(), wintypes.UINT()
        langs = []
        if v.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(ln)) and ln.value >= 4:
            raw = ctypes.string_at(ptr.value, ln.value)
            for i in range(0, len(raw) - 3, 4):
                langs.append("%04x%04x" % (int.from_bytes(raw[i:i + 2], "little"), int.from_bytes(raw[i + 2:i + 4], "little")))
        langs += ["040904b0", "040904e4", "000004b0"]
        for lang in langs:
            if v.VerQueryValueW(buf, "\\StringFileInfo\\%s\\CompanyName" % lang, ctypes.byref(ptr), ctypes.byref(ln)) and ln.value:
                return ctypes.wstring_at(ptr.value).strip()
    except Exception:  # noqa: BLE001
        pass
    return ""


def _signer_name(path):
    """Subject name of the embedded Authenticode signer ('' if it cannot be read)."""
    from ctypes import wintypes
    crypt32 = ctypes.windll.crypt32

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.c_void_p)]

    class ALG(ctypes.Structure):
        _fields_ = [("pszObjId", ctypes.c_char_p), ("Parameters", BLOB)]

    class CERT_INFO(ctypes.Structure):   # only SerialNumber and Issuer are read by CERT_FIND_SUBJECT_CERT
        _fields_ = [("dwVersion", wintypes.DWORD), ("SerialNumber", BLOB), ("SignatureAlgorithm", ALG), ("Issuer", BLOB), ("rest", ctypes.c_byte * 512)]

    class SIGNER_INFO(ctypes.Structure):
        _fields_ = [("dwVersion", wintypes.DWORD), ("Issuer", BLOB), ("SerialNumber", BLOB), ("rest", ctypes.c_byte * 256)]
    crypt32.CryptQueryObject.argtypes = [wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    crypt32.CryptMsgGetParam.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    crypt32.CertFindCertificateInStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
    crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    store, msg = ctypes.c_void_p(), ctypes.c_void_p()
    enc, content, fmt = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
    wpath = ctypes.c_wchar_p(path)
    if not crypt32.CryptQueryObject(1, wpath, 0x400, 2, 0, ctypes.byref(enc), ctypes.byref(content), ctypes.byref(fmt), ctypes.byref(store), ctypes.byref(msg), None):
        return ""
    try:
        size = wintypes.DWORD(0)
        if not crypt32.CryptMsgGetParam(msg, 6, 0, None, ctypes.byref(size)):
            return ""
        raw = ctypes.create_string_buffer(size.value)
        if not crypt32.CryptMsgGetParam(msg, 6, 0, raw, ctypes.byref(size)):
            return ""
        si = ctypes.cast(raw, ctypes.POINTER(SIGNER_INFO)).contents
        ci = CERT_INFO()
        ci.Issuer, ci.SerialNumber = si.Issuer, si.SerialNumber
        ctx = crypt32.CertFindCertificateInStore(store, 0x10001, 0, 0x000B0000, ctypes.byref(ci), None)
        if not ctx:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(256)
            crypt32.CertGetNameStringW(ctx, 4, 0, None, buf, 256)
            return buf.value
        finally:
            crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
            crypt32.CertFreeCertificateContext(ctx)
    finally:
        try:
            crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
            crypt32.CryptMsgClose.argtypes = [ctypes.c_void_p]
            if store:
                crypt32.CertCloseStore(store, 0)
            if msg:
                crypt32.CryptMsgClose(msg)
        except Exception:  # noqa: BLE001
            pass


def _verify(path, catalog=None):
    """WinVerifyTrust on a file, or on a catalog member. Returns the LONG status (0 = trusted). No revocation/network."""
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort), ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

    class FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR), ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class CAT_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD), ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                    ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE), ("pbCalculatedFileHash", ctypes.c_void_p),
                    ("cbCalculatedFileHash", wintypes.DWORD), ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", wintypes.HANDLE)]

    class WTD(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p), ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD), ("pUnion", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR), ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]
    action = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    wt = ctypes.windll.wintrust
    wt.WinVerifyTrust.argtypes = [ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.c_void_p]
    wt.WinVerifyTrust.restype = ctypes.c_long
    d = WTD()
    d.cbStruct = ctypes.sizeof(WTD)
    d.dwUIChoice = 2            # WTD_UI_NONE
    d.fdwRevocationChecks = 0   # WTD_REVOKE_NONE
    d.dwProvFlags = 0x10 | 0x1000   # no revocation check, cache-only URL retrieval: never touches the network
    if catalog is None:
        fi = FILE_INFO(ctypes.sizeof(FILE_INFO), path, None, None)
        d.dwUnionChoice, d.pUnion = 1, ctypes.cast(ctypes.pointer(fi), ctypes.c_void_p)
        keep = fi
    else:
        d.dwUnionChoice, d.pUnion = 2, ctypes.cast(ctypes.pointer(catalog), ctypes.c_void_p)
        keep = catalog
    d.dwStateAction = 1         # WTD_STATEACTION_VERIFY
    res = wt.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(d))
    d.dwStateAction = 2         # WTD_STATEACTION_CLOSE
    wt.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(d))
    del keep
    return res


def _catalog_verify(path):
    """Windows files are usually signed through a catalog instead of an embedded signature. Returns status or None."""
    from ctypes import wintypes
    wt, k32 = ctypes.windll.wintrust, ctypes.windll.kernel32

    class CATALOG_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", ctypes.c_wchar * 260)]

    class CAT_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD), ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                    ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE), ("pbCalculatedFileHash", ctypes.c_void_p),
                    ("cbCalculatedFileHash", wintypes.DWORD), ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", wintypes.HANDLE)]
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    wt.CryptCATAdminAcquireContext.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminCalcHashFromFileHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminEnumCatalogFromHash.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    wt.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    wt.CryptCATCatalogInfoFromContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
    wt.CryptCATAdminReleaseCatalogContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    admin = ctypes.c_void_p()
    if not wt.CryptCATAdminAcquireContext(ctypes.byref(admin), None, 0):
        return None
    h = k32.CreateFileW(path, 0x80000000, 7, None, 3, 0, None)
    if h in (None, ctypes.c_void_p(-1).value, -1):
        wt.CryptCATAdminReleaseContext(admin, 0)
        return None
    cat = None
    try:
        size = wintypes.DWORD(0)
        wt.CryptCATAdminCalcHashFromFileHandle(h, ctypes.byref(size), None, 0)
        if not size.value:
            return None
        hb = ctypes.create_string_buffer(size.value)
        if not wt.CryptCATAdminCalcHashFromFileHandle(h, ctypes.byref(size), hb, 0):
            return None
        tag = "".join("%02X" % b for b in hb.raw[:size.value])
        cat = wt.CryptCATAdminEnumCatalogFromHash(admin, hb, size.value, 0, None)
        if not cat:
            return None
        ci = CATALOG_INFO()
        ci.cbStruct = ctypes.sizeof(CATALOG_INFO)
        if not wt.CryptCATCatalogInfoFromContext(cat, ctypes.byref(ci), 0):
            return None
        info = CAT_INFO()
        info.cbStruct = ctypes.sizeof(CAT_INFO)
        info.pcwszCatalogFilePath = ci.wszCatalogFile
        info.pcwszMemberTag = tag
        info.pcwszMemberFilePath = path
        info.hMemberFile = h
        info.pbCalculatedFileHash = ctypes.cast(hb, ctypes.c_void_p)
        info.cbCalculatedFileHash = size.value
        info.hCatAdmin = admin
        return _verify(path, info)
    finally:
        if cat:
            wt.CryptCATAdminReleaseCatalogContext(admin, cat, 0)
        k32.CloseHandle(h)
        wt.CryptCATAdminReleaseContext(admin, 0)


NO_SIG = {0x800B0100, 0x800B0003, 0x800B0001}      # no signature / form unknown / provider unknown


def check_signature(path):
    """{'state': signed|unsigned|invalid|unknown, 'publisher', 'detail', 'company'} for one file."""
    long_path = path if not (len(path) > 240 and not path.startswith("\\\\?\\")) else "\\\\?\\" + path
    res = _verify(long_path) & 0xFFFFFFFF
    company = company_name(path)
    if res == 0:
        try:
            name = _signer_name(long_path)
        except Exception:  # noqa: BLE001
            name = ""
        return {"state": "signed", "publisher": name or company, "company": company, "detail": "Valid digital signature"}
    if res in NO_SIG:
        cres = _catalog_verify(long_path)
        if cres is not None and (cres & 0xFFFFFFFF) == 0:
            return {"state": "signed", "publisher": company or "Microsoft Windows", "company": company, "detail": "Signed through a Windows security catalog"}
        return {"state": "unsigned", "publisher": company, "company": company, "detail": "No digital signature"}
    reasons = {0x80096010: "The file was changed after it was signed", 0x800B0109: "Signed by an untrusted publisher", 0x800B0101: "The signing certificate has expired",
               0x800B010C: "The signing certificate was revoked", 0x800B0004: "The signature is not trusted"}
    return {"state": "invalid", "publisher": company, "company": company, "detail": reasons.get(res, "Signature check failed (0x%08X)" % res)}
