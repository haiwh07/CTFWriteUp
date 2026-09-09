# Challenge: Out Of Bound

## Vấn đề
- [File challenge](https://github.com/haiwh07/CTFWriteUp/blob/main/dreamhack/oob/out_of_bound)
- 
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
