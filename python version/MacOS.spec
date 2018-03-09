# -*- mode: python -*-

block_cipher = None


a = Analysis(['wxParaCrypt.py'],
             pathex=['/Users/jonathan/ParaCrypt-1.0.0RC2.5/dist'],
             binaries=[],
             datas=[('ParaCryptArt/*.*','ParaCryptArt'),('ParaCryptHelp/*.*','ParaCryptHelp'),
             ('Version.xml','.')],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='wxParaCrypt',
          debug=False,
          strip=False,
          upx=True,
          console=False )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='wxParaCrypt')
app = BUNDLE(coll,
             name='wxParaCrypt.app',
             icon='ParaCryptArt/ParaCrypt.icns',
             bundle_identifier=None)
