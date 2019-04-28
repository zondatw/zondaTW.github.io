---
layout: post
title:  "Unicorn engine tutorial 練習 - part 5"
date:   2019-04-28 14:25:24 +0800
categories: Reversing
---

## 前言

上一篇把unicorn task 3 完成了，接下來就繼續造這篇[Unicorn Engine tutorial][Unicorn_Engine_tutorial]來解下一題摟~  
這也是最後一題瞜~  

## 練習 4

這次是個arm的題目:  

```text
# file task4
task4: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=3dbf508680ba3d023d3422025954311e1d8fb4a1, not stripped
```

一樣把他丟到Ghidra中分析:  

```c
int ccc(uint uParm1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (uParm1 == 0) {
    iVar3 = 5;
  }
  else {
    if (uParm1 == 1) {
      iVar3 = 8;
    }
    else {
      if (uParm1 == 2) {
        iVar3 = 3;
      }
      else {
        if (uParm1 == 3) {
          iVar3 = 1;
        }
        else {
          iVar1 = ccc(uParm1 >> 1);
          iVar2 = ccc(uParm1 - 1);
          iVar3 = ccc(uParm1 - 3);
          iVar3 = iVar2 * iVar1 + iVar3;
        }
      }
    }
  }
  return iVar3;
}

undefined4 main(void)

{
  undefined4 uVar1;
  
  uVar1 = ccc(10000);
  printf(&UNK_000745a4,uVar1);
  return 0;
}
```

### 模擬

跟task 1一樣先想辦法讓它能動。  

```python
from unicorn import *
from unicorn.arm_const import *


filename = "./task4"

base_adr = 0x0010000
stack_adr = 0x400000
stack_size = 1024 * 1024

main_start_adr = 0x00010584
main_end_adr = 0x000105bc
main_ccc_end = 0x00010594
ccc_start = 0x000104d0
ccc_end = 0x00010580

def read(name):
    with open(name, "rb") as f:
        return f.read()

def u32(data):
    return struct.unpack("I", data)[0]

def p32(num):
    return struct.pack("I", num)

def hook_code(mu, address, size, user_data):
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

try:
    mu = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
    mu.mem_map(base_adr, 1024 * 1024)
    mu.mem_map(stack_adr, stack_size)

    mu.mem_write(base_adr, read(filename))
    mu.reg_write(UC_ARM_REG_SP, stack_adr + stack_size - 1)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    mu.emu_start(main_start_adr, main_end_adr)
except UcError as e:
    print("ERROR: %s" % e)
```

### 優化

跟task 1一樣，將ccc算過的值存下來。  

```python
from unicorn import *
from unicorn.arm_const import *


filename = "./task4"

base_adr = 0x0010000
stack_adr = 0x400000
stack_size = 1024 * 1024

main_start_adr = 0x00010584
main_end_adr = 0x000105bc
main_ccc_end = 0x00010594
ccc_start = 0x000104d0
ccc_end = 0x00010580

ret_instr = 0x00029388

dict_ccc_result = {}
stack_buf = []

def read(name):
    with open(name, "rb") as f:
        return f.read()

def u32(data):
    return struct.unpack("I", data)[0]

def p32(num):
    return struct.pack("I", num)

def hook_code(mu, address, size, user_data):
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

    if address == ccc_start:
        arg0 = mu.reg_read(UC_ARM_REG_R3)

        if arg0 in dict_ccc_result:
            mu.reg_write(UC_ARM_REG_R0, dict_ccc_result[arg0])
            mu.reg_write(UC_ARM_REG_PC, ret_instr)
        else:
            stack_buf.append(arg0)

    elif address == ccc_end:
        arg0 = stack_buf.pop()
        ret_val = mu.reg_read(UC_ARM_REG_R0)
        dict_ccc_result[arg0] = ret_val

    elif address == main_ccc_end:
        ret_val = mu.reg_read(UC_ARM_REG_R0)
        print(f"Result: {ret_val}")

try:
    mu = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
    mu.mem_map(base_adr, 1024 * 1024)
    mu.mem_map(stack_adr, stack_size)

    mu.mem_write(base_adr, read(filename))
    mu.reg_write(UC_ARM_REG_SP, stack_adr + stack_size - 1)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    mu.emu_start(main_start_adr, main_end_adr)
except UcError as e:
    print("ERROR: %s" % e)
```

output:

```text
$ python task4_solve.py
Result: 2635833876
```

練習4也完成瞜~  
這一系列就暫時到這摟~~  

[Unicorn_Engine_tutorial]:http://eternal.red/2018/unicorn-engine-tutorial/  