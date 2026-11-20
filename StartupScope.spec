# PyInstaller spec: one-file, windowed StartupScope.exe with the web UI bundled.
# Build:  pyinstaller --noconfirm --clean StartupScope.spec
a = Analysis(
    ['launcher.py'],
    pathex=['.'],
    datas=[('web', 'web')],
    hiddenimports=['server', 'startup', 'winreg_util', 'storage', 'appserver', 'winsig'],
    excludes=['tkinter', 'unittest', 'pydoc', 'test', 'numpy'],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='StartupScope',
    console=False,
    icon='startupscope.ico',
    upx=False,
    version='version_info.txt',
)
