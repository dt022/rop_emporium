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

payload = flat(
    
)

rop.raw()
print(rop.dump())

# pause()
p.send(payload)
p.send(rop.chain())

p.interactive()

# with open('out.txt', 'wb') as out:
    # out.write(payload)
