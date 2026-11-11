# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the L3 Extractor GUI (Windows & macOS).
#
# Build:
#   pip install -r requirements-build.txt
#   pyinstaller l3extractor.spec
#
from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], []
for pkg in ("customtkinter",):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

block_cipher = None

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="L3Extractor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="L3Extractor",
)

# On macOS, also wrap the collected app into a .app bundle.
app = BUNDLE(
    coll,
    name="L3Extractor.app",
    icon=None,
    bundle_identifier="com.example.l3extractor",
)
