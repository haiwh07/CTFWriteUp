# Challenge: Return Address Overwrite

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/return_address_overwrite/rao)
- Khi thực thi, chương trình kêu user nhập input bằng hàm scanf và sau đó exit.
- Checksec:
+ Arch:       amd64-64-
+ RELRO:      Partial RELRO
+ Stack:      No canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x400000)
+ Stripped:   No

## Giải pháp
- Khi check trong ida, tôi thấy hàm get_shell() chứa execve("/bin/sh", 0, 0).
- Chương trình dùng scanf nhưng **Canary tắt** nên có thể khai thác **Buffer Overflow**.
- Cùng với **PIE tắt** nên ta có thể overwrite hàm ret để trả về địa chỉ get_shell().
> Overwrite ret thành địa chỉ get_shell() để có shell.

## Quá trình
- Tính offset: Từ buf đến ret có 0x38 bytes rác.
- Địa chỉ hàm get_shell(): Ta lấy bằng exe.sym['get_shell'] vì PIE tắt nên có thể sử dụng.
> Payload = b'A'*0x38 + p64(exe.sym['get_shell']

## Script
```
// Name: rao.c
// Compile: gcc -o rao rao.c -fno-stack-protector -no-pie

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

void get_shell() {
  char *cmd = "/bin/sh";
  char *args[] = {cmd, NULL};

  execve(cmd, args, NULL);
}

int main() {
  char buf[0x28];

  init();

  printf("Input: ");
  scanf("%s", buf);

  return 0;
}
```
