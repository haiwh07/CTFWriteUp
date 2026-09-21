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
- Trong đó có 3 hàm sau:
```

```
