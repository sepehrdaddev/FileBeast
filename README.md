## Description

Script to Encrypt, Decrypt, Compress and Decompress Files using multiple Algorithms such as AES and Triple DES.

## Usage

```

          .                                                      .
        .n                   .                 .                  n.
  .   .dP                  dP                   9b                 9b.    .
 4    qXb         .       dX                     Xb       .        dXp     t
dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
  `9XXXXXXXXXXXXXXXXXXXXX"~   ~`OOO8b   d8OOO"~   ~`XXXXXXXXXXXXXXXXXXXXXP"
    `9XXXXXXXXXXXP" `9XX"   FILE   `98v8P"  BEAST  `XXP" `9XXXXXXXXXXXP"
        ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                        )b.  .dbo.dP"`v"`9b.odb.  .dX(
                      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                     dXXXXXXXXXXXP"   .   `9XXXXXXXXXXXb
                    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                    9XXb"   `XXXXXb.dX|Xb.dXXXXX"   `dXXP
                     `"      9XXXXXX(   )XXXXXXP      `"
                              XXXX X.`v".X XXXX
                              XP^X"`b   d"`X^XX
                              X. 9  `   "  P )X
                              `b  `       "  d"
                               `             "
                          FileBeast by Sepehrdad Sh


Main Menu:

 Encrypt
 Decrypt
 Compress
 Decompress
 Version
 Exit

FileBeast (Main)>
```

## How do I get set up?

1.  Download ZipFile from : https://github.com/sepehrdaddev/FileBeast/archive/master.zip and extract it or
    Run `git clone https://github.com/sepehrdaddev/FileBeast.git` in the shell
1.  Install python 3.x
1.  Run `pip install -r requirements.txt` in shell
1.  Run `python FileBeast.py` in shell

## How to Compile

### Using pyinstaller

- Download pyinstaller: https://github.com/pyinstaller/pyinstaller
- Create the executable file:`python pyinstaller.py --onefile FileBeast.py`

### For Windows only

- To get a better compatibility between systems, msvcp100.dll and msvcr100.dll could be added. These files could be found in "C:\Windows\System32\". Place it on the root folder of the pyinstaller directory.

- Create a .spec file adding all options wanted. Mine is as follow:

```
# -*- mode: python -*-
import sys
a = Analysis(['FileBeast.py'],
             pathex=[''],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
for d in a.datas:
  if 'pyconfig' in d[0]:
    a.datas.remove(d)
    break
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
		  a.binaries + [('msvcp100.dll', 'msvcp100.dll', 'BINARY'),
						('msvcr100.dll', 'msvcr100.dll', 'BINARY')]
		  if sys.platform == 'win32' else a.binaries,
          a.zipfiles,
          a.datas,
          name='FileBeast.exe',
          debug=False,
          strip=None,
          upx=True,
          console=True)

```

- Generate your executable file: `python pyinstaller.py --onefile FileBeast.spec`

## Get Involved

**Please, send us pull requests!**
