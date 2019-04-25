---
layout: post
title:  "Pyinstaller Decompile"
date:   2019-04-25 23:59:00 +0800
categories: Reversing
---
這是很久以前玩pyinstaller decompile的筆記，現在把它搬來這裡。  

## Create exe by pyinstaller

### Environment

| tool        | version |
| ----------- | ------- |
| python      | 3.6.7   |
| PyInstaller | 3.4     |

### Build exe file

#### source code
```python
# my_script.py
print("Hello World!")
```

#### build
`pyinstaller my_script.py`  
build完，執行檔會在dist中。  

#### Execution
```
$ ./my_script.exe
Hello World!
```

## Decompile pyinstaller

### Environment

| tool        | version |
| ----------- | ------- |
| python      | 3.6.7   |
| [pyinstxtractor](https://sourceforge.net/projects/pyinstallerextractor/) | 1.8     |
| uncompyle6      | 3.2.5   |

### Decompile

#### Extract
`python pyinstxtractor.py my_script.exe` 
完成後會出現`my_script.exe_extracted`的資料夾，  
在裡面找到跟執行檔名稱一樣的檔案，打開來看如下:  
![](/assets/images/2020-04-25-pyinstaller_decompile/orig.png)  

#### uncompyle
將檔名改成`.pyc`  
指令: `uncompyle6.exe my_script.pyc`  
再來如果直接decompile的話會出現下面的錯誤訊息:  
```text
$ uncompyle6.exe my_script.pyc
Traceback (most recent call last):
  File "c:\python36\lib\site-packages\xdis\load.py", line 131, in load_module_from_file_object
    float_version = float(magics.versions[magic][:3])
KeyError: b'\xe3\x00\x00\x00'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "c:\python36\lib\runpy.py", line 193, in _run_module_as_main
    "__main__", mod_spec)
  File "c:\python36\lib\runpy.py", line 85, in _run_code
    exec(code, run_globals)
  File "C:\Python36\Scripts\uncompyle6.exe\__main__.py", line 9, in <module>
  File "c:\python36\lib\site-packages\uncompyle6\bin\uncompile.py", line 181, in main_bin
    **options)
  File "c:\python36\lib\site-packages\uncompyle6\main.py", line 232, in main
    linemap_stream, do_fragments)
  File "c:\python36\lib\site-packages\uncompyle6\main.py", line 133, in decompile_file
    source_size) = load_module(filename, code_objects)
  File "c:\python36\lib\site-packages\xdis\load.py", line 107, in load_module
    fast_load=fast_load, get_code=get_code)
  File "c:\python36\lib\site-packages\xdis\load.py", line 136, in load_module_from_file_object
    (ord(magic[0:1])+256*ord(magic[1:2]), filename))
ImportError: Unknown magic number 227 in my_script.pyc
```
這表示前輟magic number不符合pyc規範  

將magic number補回去(可參考其他被extract的pyc檔)  
![](/assets/images/2020-04-25-pyinstaller_decompile/modify.png)

再執行一次，就成功喽~  
```
$ uncompyle6.exe my_script.pyc
# uncompyle6 version 3.2.5
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.6.7 (v3.6.7:6ec5cf24b7, Oct 20 2018, 13:35:33) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: my_script.py
print('Hello World!')
# okay decompiling my_script.pyc
```
