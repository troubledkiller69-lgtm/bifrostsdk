# -*- mode: python ; coding: utf-8 -*-
# BIFROST SDK backend build — produces dist/api_server.exe
# All engine/core submodules are collected explicitly because the engine
# registry imports dumpers dynamically via importlib, which PyInstaller's
# static bytecode analysis would otherwise miss (the old api_server_new3/4
# builds shipped without working engine modules).

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []
hiddenimports += collect_submodules('core')
hiddenimports += collect_submodules('engines')
hiddenimports += collect_submodules('contracts')
hiddenimports += collect_submodules('config')

# Third-party modules imported dynamically inside functions
hiddenimports += [
    'pymem', 'pymem.process', 'pymem.exception',
    'pefile', 'psutil', 'jsonschema',
]

a = Analysis(
    ['api_server.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('contracts/bifrost_protocol.json', 'contracts'),
        ('contracts/sdk_output_schema.json', 'contracts'),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'PIL', 'scipy'],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='api_server',
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
)
