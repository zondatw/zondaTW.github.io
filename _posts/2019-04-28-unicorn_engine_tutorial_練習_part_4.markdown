---
layout: post
title:  "Unicorn engine tutorial 練習 - part 4"
date:   2019-04-28 13:51:24 +0800
categories: [Reversing, Unicorn engine]
---

## 前言

上一篇把unicorn task 2 完成了，接下來就繼續造這篇[Unicorn Engine tutorial][Unicorn_Engine_tutorial]來解下一題摟~

## 練習 3

這次的題目主要是讓一個不可能return 1的function能return 1。  

```c
// gcc function.c -m32 -o function
int strcmp(char *a, char *b)
{
    //get length
    int len = 0;
    char *ptr = a;
    while(*ptr)
    {
        ptr++;
        len++;
    }

    //comparestrings
    for(int i=0; i<=len; i++)
    {
        if (a[i]!=b[i])
            return 1;
    }

    return 0;
}

__attribute__((stdcall))
int  super_function(int a, char *b)
{
    if (a==5 && !strcmp(b, "batman"))
    {
        return 1;
    }
    return 0;
}

int main()
{
    super_function(1, "spiderman");
}  
```

## 分析

想要改變他，有很多種方式，這次來試試改變參數的作法，  
因此我們首先抓抓看呼叫`super_function`時的參數。

```python
import struct

from unicorn import *
from unicorn.x86_const import *


filename = "./function"

base_adr = 0x400000
stack_adr = 0x0
stack_size = 1024 * 1024

main_start_adr = 0x000005B4 + base_adr
main_end_adr = 0x000005D5 + base_adr
super_function_start = 0x0000057B + base_adr
super_function_end = 0x000005B1 + base_adr

def read(name):
    with open(name, "rb") as f:
        return f.read()

def u32(data):
    return struct.unpack("I", data)[0]

def p32(num):
    return struct.pack("I", num)

def hook_code(mu, address, size, user_data):
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

    if address == super_function_start:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_adr = u32(mu.mem_read(esp, 4))
        arg0 = u32(mu.mem_read(esp + 4, 4))
        arg1 = u32(mu.mem_read(esp + 8, 4))
        arg1_string = mu.mem_read(arg1, 16)

        print("[*] super function start")
        print(f"esp: {hex(esp)}")
        print(f"ret_adr: {hex(ret_adr)}")
        print(f"arg0: {arg0}")
        print(f"arg1: {hex(arg1)} -> {arg1_string}")

    elif address == super_function_end:
        ret_val = mu.reg_read(UC_X86_REG_EAX)

        print("[*] super function end")
        print(f"Return value: {hex(ret_val)}")

try:
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(base_adr, 1024 * 1024)
    mu.mem_map(stack_adr, stack_size)

    mu.mem_write(base_adr, read(filename))
    mu.reg_write(UC_X86_REG_ESP, stack_adr + stack_size - 1)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    mu.emu_start(main_start_adr, main_end_adr)
except UcError as e:
    print("ERROR: %s" % e)
```

output:

```text
$ python task3_solve.py
[*] super function start
esp: 0xfffef
ret_adr: 0x4005cf
arg0: 1
arg1: 0x400667 -> bytearray(b'spiderman\x00\x00\x00\x00\x01\x1b\x03')
[*] super function end
Return value: 0x0
```

## 變更參數

當arg0 = 5 以及 arg1 = batman的時候，才會return 1，  
所以我們現在要把參數改變一下。  

```python
import struct

from unicorn import *
from unicorn.x86_const import *


filename = "./function"

base_adr = 0x400000
stack_adr = 0x0
stack_size = 1024 * 1024

main_start_adr = 0x000005B4 + base_adr
main_end_adr = 0x000005D5 + base_adr
super_function_start = 0x0000057B + base_adr
super_function_end = 0x000005B1 + base_adr

def read(name):
    with open(name, "rb") as f:
        return f.read()

def u32(data):
    return struct.unpack("I", data)[0]

def p32(num):
    return struct.pack("I", num)

def hook_code(mu, address, size, user_data):
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

    if address == super_function_start:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_adr = u32(mu.mem_read(esp, 4))
        arg0 = u32(mu.mem_read(esp + 4, 4))
        arg1 = u32(mu.mem_read(esp + 8, 4))
        arg1_string = mu.mem_read(arg1, 16)

        print("[*] super function start - original")
        print(f"esp: {hex(esp)}")
        print(f"ret_adr: {hex(ret_adr)}")
        print(f"arg0: {arg0}")
        print(f"arg1: {hex(arg1)} -> {arg1_string}")
        print("")

        mu.mem_write(esp + 4, p32(5))
        mu.mem_write(arg1, b"batman\x00")

        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_adr = u32(mu.mem_read(esp, 4))
        arg0 = u32(mu.mem_read(esp + 4, 4))
        arg1 = u32(mu.mem_read(esp + 8, 4))
        arg1_string = mu.mem_read(arg1, 16)

        print("[*] super function start - modify")
        print(f"esp: {hex(esp)}")
        print(f"ret_adr: {hex(ret_adr)}")
        print(f"arg0: {arg0}")
        print(f"arg1: {hex(arg1)} -> {arg1_string}")
        print("")

    elif address == super_function_end:
        ret_val = mu.reg_read(UC_X86_REG_EAX)

        print("[*] super function end")
        print(f"Return value: {hex(ret_val)}")

try:
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(base_adr, 1024 * 1024)
    mu.mem_map(stack_adr, stack_size)

    mu.mem_write(base_adr, read(filename))
    mu.reg_write(UC_X86_REG_ESP, stack_adr + stack_size - 1)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    mu.emu_start(main_start_adr, main_end_adr)
except UcError as e:
    print("ERROR: %s" % e)
```

output:  

```text
$ python task3_solve.py
[*] super function start - original
esp: 0xfffef
ret_adr: 0x4005cf
arg0: 1
arg1: 0x400667 -> bytearray(b'spiderman\x00\x00\x00\x00\x01\x1b\x03')

[*] super function start - modify
esp: 0xfffef
ret_adr: 0x4005cf
arg0: 5
arg1: 0x400667 -> bytearray(b'batman\x00an\x00\x00\x00\x00\x01\x1b\x03')

[*] super function end
Return value: 0x1
```

練習3完成瞜~  

[Unicorn_Engine_tutorial]:http://eternal.red/2018/unicorn-engine-tutorial/  