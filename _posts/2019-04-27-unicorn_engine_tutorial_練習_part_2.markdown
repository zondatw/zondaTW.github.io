---
layout: post
title:  "Unicorn engine tutorial 練習 - part 2"
date:   2019-04-27 11:41:24 +0800
categories: [Reversing, Unicorn engine]
---

## 前言

上一篇把unicorn裝完好了，也稍微懂了怎麼使用。  
那接下來就開始造這篇[Unicorn Engine tutorial][Unicorn_Engine_tutorial]來一個一個練習題慢慢玩摟~

## 練習 1

練習1的hxp CTF2017的題目，叫做Fibonacci，  
題目會給一個binary檔，執行後會以非常慢的速度慢慢的產生Flag，因此我們要來優化它。  

那首先就是要先分析它在做什麼摟~  
這方面就是將它直接丟進IDA Pro或是Ghidra，讓它們幫忙decompile，我這邊是用Ghidra來做。  

```c
undefined8 FUN_004004e0(void)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  uint uVar4;
  uint uVar5;
  long lVar6;
  uint uVar7;
  ulong uVar8;
  int local_1c [3];
  
  iVar2 = 0;
  setbuf(stdout,(char *)0x0);
  printf("The flag is: ");
  uVar8 = 0x49;
  pbVar3 = &DAT_004007e1;
  while( true ) {
    lVar6 = 0;
    do {
      uVar7 = (uint)uVar8;
      local_1c[0] = 0;
      FUN_00400670((ulong)(uint)(iVar2 + (int)lVar6),local_1c);
      bVar1 = (byte)lVar6;
      lVar6 = lVar6 + 1;
      uVar4 = local_1c[0] << (bVar1 & 0x1f);
      uVar5 = uVar4 ^ uVar7;
      uVar8 = (ulong)uVar5;
    } while (lVar6 != 8);
    iVar2 = iVar2 + 8;
    if ((char)uVar4 == (char)uVar7) break;
    _IO_putc((int)(char)uVar5,(_IO_FILE *)stdout);
    uVar8 = (ulong)*pbVar3;
    pbVar3 = pbVar3 + 1;
  }
  _IO_putc(10,(_IO_FILE *)stdout);
  return 0;
}
```

```c
ulong FUN_00400670(int iParm1,uint *puParm2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  ulong uVar4;
  
  if (iParm1 != 0) {
    if (iParm1 == 1) {
      uVar4 = FUN_00400670();
      uVar3 = (int)uVar4 - ((uint)((uVar4 & 0xffffffff) >> 1) & 0x55555555);
    }
    else {
      iVar1 = FUN_00400670((ulong)(iParm1 - 2));
      iVar2 = FUN_00400670((ulong)(iParm1 - 1));
      uVar3 = iVar2 + iVar1;
      uVar4 = (ulong)uVar3;
      uVar3 = uVar3 - (uVar3 >> 1 & 0x55555555);
    }
    uVar3 = (uVar3 >> 2 & 0x33333333) + (uVar3 & 0x33333333);
    uVar3 = (uVar3 >> 4) + uVar3;
    uVar3 = (uVar3 >> 8 & 0xf0f0f) + (uVar3 & 0xf0f0f0f);
    *puParm2 = *puParm2 ^ (uVar3 >> 0x10) + uVar3 & 1;
    return uVar4;
  }
  *puParm2 = *puParm2 ^ 1;
  return 1;
}
```

## 開始

### 第一步 模擬

首先當然先讓程式能跑在unicorn中喽~  

```python
import os
import math

from unicorn import *
from unicorn.x86_const import *

filename = "./fibonacci"
file_size = int(math.ceil(os.path.getsize(filename) / 1024) + 1) * 1024

base_adr = 0x400000
stack_adr = 0x0
stack_size = 1024 * 1024

main_start_adr = 0x004004e0
main_end_adr = 0x00400582

def read(name):
    with open(name, "rb") as f:
        return f.read()

instructions_skip_list = [0x004004EF, 0x004004f6, 0x00400502, 0x0040054F]
instructions_IO_putc_list = [0x00400560, 0x00400575]

def hook_code(mu, address, size, user_data):  
    #print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

    if address in instructions_skip_list:
        mu.reg_write(UC_X86_REG_RIP, address + size)
    elif address in instructions_IO_putc_list:
        print(chr(mu.reg_read(UC_X86_REG_RDI)))
        mu.reg_write(UC_X86_REG_RIP, address + size)

try:
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(base_adr, file_size)
    mu.mem_map(stack_adr, stack_size)

    mu.mem_write(base_adr, read(filename))
    mu.reg_write(UC_X86_REG_RSP, stack_adr + stack_size - 1)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    mu.emu_start(main_start_adr, main_end_adr)
except UcError as e:
    print("ERROR: %s" % e)
```

稍微簡單解釋程式。  

* 定義`Uc(UC_ARCH_X86, UC_MODE_64)`架構為x86-64  
* 定義程式的base address和memory size  
* 定義stack的address和size  
* 將程式放到base address中  
* 將stack的memory address寫到RSP中  
* 定義hook function: 用來debug程式在哪邊crash或者是修改行程，比方說:  
  * 0x004004EF mov RDI,qword ptr [stdout]這段因為stdout放在bss區段，而這邊未定義bss區段，所以會crash，以及一些會用到glibc的function也會crash。
  * 還有當執行到output的function時，改成把RDI的值取出，透過python print出來。  
* 執行程式從main開始到main的return 0結束

### 第二步 優化

再來就是要縮短時間，而這邊耗最多時間的就是一直算重複的費式數列，因此我們來試著儲存算過的結果，就不用一直重複算喽~  

主要有2個步驟:  

1. 判斷現在的參數是不是算過的，是的話就直接回傳參數
2. 算完後，把結果存起來

function的主體大概是:  

1. 傳入2個參數number, ptrNumber
2. return 1個值，但因為第二個參數是pointer的，而程式當中會去改變這個值，當回到主程式時也會用到，所以ptrNumber也算是輸出結果之一

```python
import os
import math
import struct

from unicorn import *
from unicorn.x86_const import *

filename = "./fibonacci"
file_size = int(math.ceil(os.path.getsize(filename) / 1024) + 1) * 1024

base_adr = 0x400000
stack_adr = 0x0
stack_size = 1024 * 1024

main_start_adr = 0x004004e0
main_end_adr = 0x00400582

instructions_skip_list = [0x004004EF, 0x004004f6, 0x00400502, 0x0040054F]
instructions_IO_putc_list = [0x00400560, 0x00400575]
fibonacci_start = [0x00400670]
fibonacci_end = [0x004006f1, 0x00400709]

ret_instr = 0x004005e9

stack_buf = []
dict_fibonacci_result = {}

def read(name):
    with open(name, "rb") as f:
        return f.read()
        
def u32(data):
    return struct.unpack("I", data)[0]
    
def p32(num):
    return struct.pack("I", num)

def hook_code(mu, address, size, user_data):  
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

    if address in instructions_skip_list:
        mu.reg_write(UC_X86_REG_RIP, address + size)

    elif address in instructions_IO_putc_list:
        print(chr(mu.reg_read(UC_X86_REG_RDI)), end="")
        mu.reg_write(UC_X86_REG_RIP, address + size)

    elif address in fibonacci_start:
        number, ptrNumber = mu.reg_read(UC_X86_REG_RDI), mu.reg_read(UC_X86_REG_RSI)
        ptrNumber_value = u32(mu.mem_read(ptrNumber, 4))

        args = (number, ptrNumber_value)
        if args in dict_fibonacci_result:
            ret_val, ret_ptrNumber_value = dict_fibonacci_result[args]
            mu.reg_write(UC_X86_REG_RAX, ret_val)
            mu.mem_write(ptrNumber, p32(ret_ptrNumber_value))
            mu.reg_write(UC_X86_REG_RIP, ret_instr)
        else:
            stack_buf.append((number, ptrNumber, ptrNumber_value))

    elif address in fibonacci_end:
        number, ptrNumber, ptrNumber_value = stack_buf.pop()

        ret_val = mu.reg_read(UC_X86_REG_RAX)
        ret_ptrNumber_value = u32(mu.mem_read(ptrNumber, 4))

        args = (number, ptrNumber_value)
        dict_fibonacci_result[args] = (ret_val, ret_ptrNumber_value)

try:
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(base_adr, file_size)
    mu.mem_map(stack_adr, stack_size)

    mu.mem_write(base_adr, read(filename))
    mu.reg_write(UC_X86_REG_RSP, stack_adr + stack_size - 1)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    mu.emu_start(main_start_adr, main_end_adr)
except UcError as e:
    print("ERROR: %s" % e)
```

#### note

要注意不要用到已設定條件的Address，比方說ret instruction，如果用到main或fibonacci function的ret，就會做別的事情了。  

練習1就到這摟~~

[Unicorn_Engine_tutorial]:http://eternal.red/2018/unicorn-engine-tutorial/  