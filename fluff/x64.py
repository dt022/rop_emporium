from pwn import *

# file information here

context.arch = 'x86_64'
executable = ''
gdbinit = '''

'''

elf = ELF(executable)
libc = elf.libc
rop = ROP([elf, libc])

p = process(elf.path)
gdb.attach(p, gdbscript=gdbinit)

p.recvuntil("")

# THE ROP CHAIN

rop.raw()

info(rop.dump())

payload = flat(
    b'a' * 0x28, # padding
    rop.chain()    
)

# PWN
# pause()
# p.sendlineafter()
# p.recvuntil()

p.send(payload)
p.interactive()

# with open('out.txt', 'wb') as out:
    # out.write(payload)
