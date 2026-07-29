# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['aegisair_backend.py'],
    pathex=[],
    binaries=[],
    datas=[('aegisair_rf_model.onnx', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['sklearn', 'pandas', 'openpyxl', 'scipy', 'matplotlib', 'PIL', 'tensorflow', 'torch', 'lxml', 'tkinter', 'IPython', 'notebook', 'jinja2', 'sqlite3'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='aegisair_backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='aegisair_backend',
)
