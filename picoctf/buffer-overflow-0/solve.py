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
        r = remote("saturn.picoctf.net", 60804)

    return r


def main():
    r = conn()
    payload = 'A' * 100
    r.sendlineafter(':', payload)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

