import sys
from Crypto.PublicKey import RSA
from codecs import decode
from codecs import encode
import math
from struct import pack
if len(sys.argv) < 3:
    print('error: need 2 arguments')
def WHA_encrypt(inStr):
    mask = int('0x3fffffff',16)
    outhash = 0
    for b in inStr:
        intermed = ((b ^ 0xcc) << 24) | ((b ^ 0x33) << 16) | ((b ^ 0xAA) << 8) | (b ^ 0x55)
        outhash = (outhash & mask) + (intermed & mask)
    return hex(outhash)

def find_collider(plaintext):
    z = plaintext.encode()
    z = list(z)
    z.reverse()
    hsh = WHA_encrypt(plaintext.encode())
    print("Hash for input string: %s"%(hsh))
    s = "".join([chr(e) for e in z])
    collision = WHA_encrypt(s.encode())
    print("Hash for collision: %s"%(collision))
    print("Input: %s"%(plaintext))
    print("Collision: %s"%(s))
    f = open('sol_3.1.6.txt','w')
    f.write(s)
    f.close()
    return s
    
plaintext = open(sys.argv[1],'r')
text = plaintext.readline()
outfile = open(sys.argv[2],'w')
result = find_collider(text)
outfile.close()


# over complicating things
"""
def byte_3_forward(inp):
    return ((inp^0xcc)<<24)
def byte_3_backward(outp):
    return((outp>>24)^0xcc)
def byte_2_forward(inp):
    return ((inp^0x33)<<16)
def byte_2_backward(outp):
    return((outp>>16)^0x33)
def byte_1_forward(inp):
    return((inp^0xaa)<<8)
def byte_1_backward(outp):
    return((outp>>8)^0xaa)
def byte_0_forward(inp):
    return (inp^0x55)
def byte_0_backward(outp):
    return (outp^0x55)
def flip_endianess(inp):
    out = ((inp&0x0000ffff)<<16)|((inp&0xffff0000)>>16)|((inp&0x00ff00ff) << 8)|((inp&0xff00ff00)>>8)
    return out
def WHA_reverse(inHash):
    mask = int('0x3fffffff',16)
    inHash = int(inHash,16)
    inHash = pack("<I", inHash)
    inHash = encode(inHash, 'hex')
    inHash = int(inHash, 16)
    outStr = b''
    res = 0
    while (inHash > 0):
        print("Inhash: %x"%(inHash))
        intermed = byte_3_backward(inHash) & byte_2_backward(inHash) & byte_1_backward(inHash) & byte_0_backward(inHash)
        inHash >>= 8
        print("Intermed: %x"%(intermed))
        #print(chr(intermed))
        #res += intermed
        #inHash -= res
        #intermed = ((res ^ 0x55)) | ((res ^ 0xAA) >> 8) | ((res ^ 0x33) >> 16) | ((res ^ 0xcc) >> 24)
        #inHash = inHash & intermed
        #intermed = hex(intermed)
        #print(inHash)
        #print(intermed)
    print(res)
"""

