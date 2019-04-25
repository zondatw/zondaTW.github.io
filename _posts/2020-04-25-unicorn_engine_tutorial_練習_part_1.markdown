---
layout: post
title:  "Unicorn engine tutorial 練習 - part 1"
date:   2019-04-25 23:59:24 +0800
categories: Reversing
---

## 前言

最近突然想玩玩[Unicorn engine][unicorn_engine]，然後剛好找到這篇教學文章[Unicorn Engine tutorial][Unicorn_Engine_tutorial]，就來玩玩喽~  

稍微介紹一下，unicorn engine主要是一個支援多種架構的模擬器，可以拿來玩一些reversing的東西，例如:

* 惡意程式分析
* CTF
* Fuzzing


## 開始

unicorn支援蠻多語言的，而這邊主要會使用python來做操作。  
首先當然就是安裝喽: `pip install unicorn`  

安裝完後，來用官方提供的[test1.py][test1_py]來檢測一下有沒有安裝成功:  

```python
from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *

# code to be emulated
X86_CODE32 = b"\x41\x4a" # INC ecx; DEC edx

# memory address where emulation starts
ADDRESS = 0x1000000

print("Emulate i386 code")
try:
    # Initialize emulator in X86-32bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)

    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, X86_CODE32)

    # initialize machine registers
    mu.reg_write(UC_X86_REG_ECX, 0x1234)
    mu.reg_write(UC_X86_REG_EDX, 0x7890)

    # emulate code in infinite time & unlimited instructions
    mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))

    # now print out some registers
    print("Emulation done. Below is the CPU context")

    r_ecx = mu.reg_read(UC_X86_REG_ECX)
    r_edx = mu.reg_read(UC_X86_REG_EDX)
    print(">>> ECX = 0x%x" %r_ecx)
    print(">>> EDX = 0x%x" %r_edx)

except UcError as e:
    print("ERROR: %s" % e)
```

output:  

```text
$ python test1.py
Emulate i386 code
Emulation done. Below is the CPU context
>>> ECX = 0x1235
>>> EDX = 0x788f
```

範例程式的內容其實蠻簡單就能理解的，  
1. 定義unicorn的架構`Uc(UC_ARCH_X86, UC_MODE_32)`，定義為x86-32的架構。  
2. 定義memory的起始位址與大小`mu.mem_map(ADDRESS, 2 * 1024 * 1024)`，從0x1000000開始分配2MB的記憶體。  
3. 初始化ecx, edx的初始值，`mu.reg_write(UC_X86_REG_ECX, 0x1234)`和`mu.reg_write(UC_X86_REG_EDX, 0x7890)`，分別定義ecx = 0x1234, edx = 0x7890。  
4. 將一個功能是`INC ecx; DEC edx`的shell code放進memory中 `mu.mem_write(ADDRESS, X86_CODE32)`。  
5. 啟動模擬器`emu_start`，這函數官方提到下面4個參數，而在這個例子`mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))`，所代表的是模擬的記憶體位址是0x1000000，當執行到X86_CODE32的記憶體位址後結束，而因為沒設定模擬時間與指令數，所以是無限:
    * 模擬的記憶體位址
    * 模擬停止的記憶體位址
    * 模擬的時間
    * 模擬的指令數
6. 讀取ecx, edx的值

那這部分就先到這邊  
to be continued~  

[unicorn_engine]:http://www.unicorn-engine.org/  
[Unicorn_Engine_tutorial]:http://eternal.red/2018/unicorn-engine-tutorial/  
[test1_py]:https://www.unicorn-engine.org/docs/tutorial.html  