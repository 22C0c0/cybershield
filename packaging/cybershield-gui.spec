# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the CyberShield GUI.

Produces a standalone executable (cybershield-gui) bundling the GUI,
all module engines and shared config/rules data. Build with:

    python -m PyInstaller packaging/cybershield-gui.spec

Output: dist/cybershield-gui (.exe / .bin / .app depending on platform).
"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parent  # project root (packaging/..)

datas = []
datas += collect_data_files("modules", include_py_files=False)

hiddenimports = []
hiddenimports += collect_submodules("modules")
hiddenimports += collect_submodules("shared")
hiddenimports += ["scapy", "scapy.all", "scapy.main", "scapy.arch"]

block_cipher = None

a = Analysis(
    [str(ROOT / "gui/app.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "tkinter",
        "IPython",
        "jupyter",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="cybershield-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # macOS .app bundle
    macos_bundle_identifier="com.cybershield.gui",
)