---
layout: post
title:  "Decompile encrypted pyinstaller exe"
date:   2021-01-12 20:57:00 +0800
categories: Reversing
---

## 前言

最近公司的某tool用到PyInstaller並且看到裡面有用encrypted的功能，身為一個逆向愛好者，一看到就想~~拆~~理解它，所以就來研究囉～  

## Build demo file

### 環境

| tool        | version |
| ----------- | ------- |
| python      | 3.7.3   |
| PyInstaller | 4.1     |

### Create main.py

```python
from pkg import secret_func

print("Hello World~~~")

secret_func()
```

### Create pkg.py

```python
def secret_func():
    print("I'm secret~~~~~")
```

### Create main.spec

```spec
# -*- mode: python ; coding: utf-8 -*-

block_cipher = pyi_crypto.PyiBlockCipher(key='0123456789ABCDEF')


a = Analysis(
    ['main.py'],
    pathex=['C:\self\programs\deTest\pytest'], # change to your path
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='main',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True
)
```

### Build

```shell
$ ls
main.py  main.spec  pkg.py
$ pyinstaller main.spec
$ .\dist\main.exe
Hello World~~~
I'm secret~~~~~
```

## Decompile

沒有加密的可以參考我以前的文章[Pyinstaller Decompile](https://zondatw.github.io/2019/pyinstaller_decompile/)  

### 環境

| tool        | version |
| ----------- | ------- |
| python      | 3.7.3   |
| [pyinstxtractor](https://sourceforge.net/projects/pyinstallerextractor/) | 1.9     |
| uncompyle6      | 3.7.4   |
| tinyaes      | 1.0.1   |

### 解開exe

```shell
$ python pyinstxtractor.py main.exe
pyinstxtractor.py:86: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
[*] Processing main.exe
[*] Pyinstaller version: 2.1+
[*] Python version: 37
[*] Length of package: 5752857 bytes
[*] Found 63 files in CArchive
[*] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap
[+] Possible entry point: main
[*] Found 134 files in PYZ archive
[!] Error: Failed to decompress __future__, probably encrypted. Extracting as is.
[!] Error: Failed to decompress _compat_pickle, probably encrypted. Extracting as is.
[!] Error: Failed to decompress _compression, probably encrypted. Extracting as is.
[!] Error: Failed to decompress _py_abc, probably encrypted. Extracting as is.
...
[!] Error: Failed to decompress pkg, probably encrypted. Extracting as is.
...
[!] Error: Failed to decompress xml.sax.xmlreader, probably encrypted. Extracting as is.
[!] Error: Failed to decompress zipfile, probably encrypted. Extracting as is.
[*] Successfully extracted pyinstaller archive: main.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

### 還原main.py

在`main.exe_extracted`找到跟執行檔名一樣的檔案`main`，並用hex editor打開來開  
![origin_main_hex](/assets/images/2021-01-12-decompile_encrypted_pyinstaller_exe/origin_main_hex.PNG)  
這邊跟以前一樣從相同的目錄下打開`struct`  
![struct_hex](/assets/images/2021-01-12-decompile_encrypted_pyinstaller_exe/struct_hex.PNG)  
將header貼到main中  
![modify_main_hex](/assets/images/2021-01-12-decompile_encrypted_pyinstaller_exe/modify_main_hex.PNG)  
把main改名成main.pyc，再使用uncompyle6解出source  

```python
uncompyle6.exe main.pyc
# uncompyle6 version 3.7.4
# Python bytecode 3.7 (3394)
# Decompiled from: Python 3.7.3 (v3.7.3:ef4ec6ed12, Mar 25 2019, 22:22:05) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: main.py
# Compiled at: 1995-09-28 00:18:56
# Size of source mod 2**32: 272 bytes
from pkg import secret_func
print('Hello World~~~')
secret_func()
# okay decompiling main.pyc
```

### 還原pkg.py

剛剛的main.py可以直接還原的原因是pyinstaller encrypted功能只加密import的檔案，  
可以從上面pyinstxtractor的步驟看到`[!] Error: Failed to decompress pkg, probably encrypted. Extracting as is.`，pkg.py是被加密起來的。  

現在我們主要處理三個面向：  
* 找到key放在哪
* 找到加解密方式
* 找到被加密的pkg.py檔案

#### 尋找key

因為覺得這工具應該是在執行時解密import的檔案，所以從source code架構中看到loader，就從裡面翻找，  
果真找到了[關鍵](https://github.com/pyinstaller/pyinstaller/blob/faee2a99deae6c9f8e1e67606a5f43af974e3fd4/PyInstaller/loader/pyimod02_archive.py#L243)  

```python
class Cipher(object):
    """
    This class is used only to decrypt Python modules.
    """
    def __init__(self):
        # At build-type the key is given to us from inside the spec file, at
        # bootstrap-time, we must look for it ourselves by trying to import
        # the generated 'pyi_crypto_key' module.
        import pyimod00_crypto_key
        key = pyimod00_crypto_key.key

        assert type(key) is str
        if len(key) > CRYPT_BLOCK_SIZE:
            self.key = key[0:CRYPT_BLOCK_SIZE]
        else:
            self.key = key.zfill(CRYPT_BLOCK_SIZE)
        assert len(self.key) == CRYPT_BLOCK_SIZE
        ...
```
發現他會import一個檔案，並且key就在裡面，結果在`main.exe_extracted`中看到了它  
![key_file_position](/assets/images/2021-01-12-decompile_encrypted_pyinstaller_exe/key_file_position.PNG)  
用hex editor打開來看  
![key_hex](/assets/images/2021-01-12-decompile_encrypted_pyinstaller_exe/key_hex.PNG)  
發現他也是pyc檔案，並且header都已經在上面了，真棒，就改成.pyc後解開來看吧`$ uncompyle6.exe pyimod00_crypto_key.pyc`，  
解開後就直接顯示key了，真的棒～  

```python
# uncompyle6 version 3.7.4
# Python bytecode 3.7 (3394)
# Decompiled from: Python 3.7.3 (v3.7.3:ef4ec6ed12, Mar 25 2019, 22:22:05) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: C:\self\programs\deTest\pytest\build\main\pyimod00_crypto_key.py
# Compiled at: 1995-09-28 00:18:56
# Size of source mod 2**32: 51 bytes
key = '0123456789ABCDEF'
# okay decompiling pyimod00_crypto_key.pyc
```

#### 尋找加解密方式

剛剛找key時其實就找到[解密的function](https://github.com/pyinstaller/pyinstaller/blob/faee2a99deae6c9f8e1e67606a5f43af974e3fd4/PyInstaller/loader/pyimod02_archive.py#L264)了  
他主要是使用tinyaes來解密  

```python
class Cipher(object):
    """
    This class is used only to decrypt Python modules.
    """
    def __init__(self):
        # At build-type the key is given to us from inside the spec file, at
        # bootstrap-time, we must look for it ourselves by trying to import
        # the generated 'pyi_crypto_key' module.
        import pyimod00_crypto_key
        key = pyimod00_crypto_key.key

        assert type(key) is str
        if len(key) > CRYPT_BLOCK_SIZE:
            self.key = key[0:CRYPT_BLOCK_SIZE]
        else:
            self.key = key.zfill(CRYPT_BLOCK_SIZE)
        assert len(self.key) == CRYPT_BLOCK_SIZE

        import tinyaes
        self._aesmod = tinyaes
        # Issue #1663: Remove the AES module from sys.modules list. Otherwise
        # it interferes with using 'tinyaes' module in users' code.
        del sys.modules['tinyaes']

    def __create_cipher(self, iv):
        # The 'AES' class is stateful, this factory method is used to
        # re-initialize the block cipher class with each call to xcrypt().
        return self._aesmod.AES(self.key.encode(), iv)

    def decrypt(self, data):
        cipher = self.__create_cipher(data[:CRYPT_BLOCK_SIZE])
        return cipher.CTR_xcrypt_buffer(data[CRYPT_BLOCK_SIZE:])
```

找到解密了，也來找找加密在哪，因為他解密用tinyaes猜測加密也是，找了一下就找到了[解密的function](https://github.com/pyinstaller/pyinstaller/blob/faee2a99deae6c9f8e1e67606a5f43af974e3fd4/PyInstaller/archive/pyz_crypto.py#L32)了～  

```python
class PyiBlockCipher(object):
    """
    This class is used only to encrypt Python modules.
    """
    def __init__(self, key=None):
        assert type(key) is str
        if len(key) > BLOCK_SIZE:
            self.key = key[0:BLOCK_SIZE]
        else:
            self.key = key.zfill(BLOCK_SIZE)
        assert len(self.key) == BLOCK_SIZE

        import tinyaes
        self._aesmod = tinyaes

    def encrypt(self, data):
        iv = os.urandom(BLOCK_SIZE)
        return iv + self.__create_cipher(iv).CTR_xcrypt_buffer(data)

    def __create_cipher(self, iv):
        # The 'AES' class is stateful, this factory method is used to
        # re-initialize the block cipher class with each call to xcrypt().
        return self._aesmod.AES(self.key.encode(), iv)
```

#### 尋找被加密的pkg.py檔案

這部份從`pyinstxtractor`來找找  

```python
try:
    data = f.read(length)
    data = zlib.decompress(data)
except:
    print('[!] Error: Failed to decompress {0}, probably encrypted. Extracting as is.'.format(fileName))
    open(destName + '.pyc.encrypted', 'wb').write(data)
    continue
```

找到source code中他會將被加密的檔案存成`{檔名}.pyc.encrypted`，接著從`main.exe_extracted/PYZ-00.pyz_extracted`發現很多`.pyc.encrypted`檔案  

#### 解密檔案

都找到後接著就是還原拉～  

```python
import zlib

import tinyaes

CHIPHER_BLOCK_SIZE = 16

key = b"0123456789ABCDEF"
pyc_header = b"\x42\x0D\x0D\x0A\x00\x00\x00\x00\x70\x79\x69\x30\x10\x01\x00\x00"

with open("main.exe_extracted\PYZ-00.pyz_extracted\pkg.pyc.encrypted", "rb") as en_f:
    with open("main.exe_extracted\PYZ-00.pyz_extracted\pkg.pyc", "wb") as de_f:
        origin_encrypted_data = en_f.read()

        # Decrypt program path: https://github.com/pyinstaller/pyinstaller/blob/faee2a99deae6c9f8e1e67606a5f43af974e3fd4/PyInstaller/loader/pyimod02_archive.py#L264
        cipher = tinyaes.AES(key, origin_encrypted_data[:CHIPHER_BLOCK_SIZE])
        decrypted_data = cipher.CTR_xcrypt_buffer(origin_encrypted_data[CHIPHER_BLOCK_SIZE:])

        plaintext = zlib.decompress(decrypted_data)

        de_f.write(pyc_header)
        de_f.write(plaintext)
```

得到pyc檔後，解開來`$ uncompyle6.exe main.exe_extracted\PYZ-00.pyz_extracted\pkg.pyc`  

```python
# uncompyle6 version 3.7.4
# Python bytecode 3.7 (3394)
# Decompiled from: Python 3.7.3 (v3.7.3:ef4ec6ed12, Mar 25 2019, 22:22:05) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: pkg.py
# Compiled at: 1995-09-28 00:18:56
# Size of source mod 2**32: 272 bytes


def secret_func():
    print("I'm secret~~~~~")
# okay decompiling main.exe_extracted\PYZ-00.pyz_extracted\pkg.pyc
```