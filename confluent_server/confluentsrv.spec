# -*- mode: python -*-

block_cipher = None


a = Analysis(['c:/Python27/Scripts/confluentsrv.py'],
             pathex=[],
             hiddenimports=[], # ['pyghmi.constants', 'pyghmi.exceptions', 'pyghmi.ipmi.console', 'pyghmi.ipmi.private.constants', 'pyghmi.ipmi.private', 'pyghmi.ipmi.private.session', 'pyghmi.ipmi.command', 'pyghmi.ipmi.events', 'pyghmi.ipmi.fru', 'pyghmi.ipmi.private.spd', 'pyghmi.ipmi.oem.lookup', 'pyghmi.ipmi.oem.generic', 'pyghmi.ipmi.oem.lenovo', 'pyghmi.ipmi.private.util', 'pyghmi.ipmi.sdr'],
             hookspath=None,
             runtime_hooks=None,
             excludes=None,
             cipher=block_cipher)
pyz = PYZ(a.pure,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='confluentsrv.exe',
          debug=False,
          strip=None,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
	       Tree('confluent/plugins', prefix='confluent/plugins'),
               strip=None,
               upx=True,
               name='confluentsrv')
