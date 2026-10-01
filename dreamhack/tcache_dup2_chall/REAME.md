# Challenge: Tcache Duplicate 2

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/tcache_dup2_chall/tcache_dup2)
- Chương trình khi thực thi như sau:
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+0h] [rbp-10h] BYREF
  int index; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  index = 0;
  initialize(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. Create heap");
      puts("2. Modify heap");
      puts("3. Delete heap");
      printf("> ");
      __isoc99_scanf("%d", &v3);
      if ( v3 != 3 )
        break;
      delete_heap();
    }
    if ( v3 <= 3 )
    {
      if ( v3 == 1 )
      {
        create_heap(index++);
      }
      else if ( v3 == 2 )
      {
        modify_heap();
      }
    }
  }
}
```
- Trong đó, gồm 3 hàm được thực thi theo thứ tự input:
```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+0h] [rbp-10h] BYREF
  int index; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  index = 0;
  initialize(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. Create heap");
      puts("2. Modify heap");
      puts("3. Delete heap");
      printf("> ");
      __isoc99_scanf("%d", &v3);
      if ( v3 != 3 )
        break;
      delete_heap();
    }
    if ( v3 <= 3 )
    {
      if ( v3 == 1 )
      {
        create_heap(index++);
      }
      else if ( v3 == 2 )
      {
        modify_heap();
      }
    }
  }
}

unsigned __int64 modify_heap()
{
  size_t nbytes; // [rsp+8h] [rbp-18h] BYREF
  unsigned __int64 v2; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(40u);
  printf("idx: ");
  __isoc99_scanf("%ld", &v2);
  if ( v2 > 6 )
    exit(0);
  printf("Size: ");
  __isoc99_scanf("%ld", &nbytes);
  if ( nbytes > 0x10 )
    exit(0);
  printf("Data: ");
  read(0, *((void **)&ptr + v2), nbytes);
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 delete_heap()
{
  unsigned __int64 v1; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("idx: ");
  __isoc99_scanf("%ld", &v1);
  if ( v1 > 6 )
    exit(0);
  if ( !*((_QWORD *)&ptr + v1) )
    exit(0);
  free(*((void **)&ptr + v1));
  return __readfsqword(0x28u) ^ v2;
}
```
- Khi dịch ngược, tôi thấy có hàm get_shell():
```
int get_shell()
{
  return system("/bin/sh");
}
```
- Checksec:
```
+ RELRO:      Partial RELRO
+ Stack:      Canary found
+ NX:         NX enabled
+ PIE:        No PIE (0x400000)
+ SHSTK:      Enabled
+ IBT:        Enabled
+ Stripped:   No
```

## Giải pháp
- 
