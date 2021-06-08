import sys
from Crypto.PublicKey import RSA
from codecs import decode
from codecs import encode
import math
if len(sys.argv) < 4:
    print('error: need 3 arguments')

# Algorithm courtesy of CS374 Fall 2020 lecture notes
# ... for some reason my VM cant take powers of large numbers
def fastpower(c,d,n):
    if d == 0:
        return 1
    if d == 1:
        return c
    else:
        k = fastpower(c,d//2,n)
        if not (d&1):
            return (k*k)%n
        else:
            return (k*k*c)%n
    return 0

ciphertext = open(sys.argv[1],'rb')
cipher = decode(ciphertext.readline(),'hex')
cipher_decimal = int(cipher.hex(),16)
ciphertext.close()

keyfile = open(sys.argv[2], 'rb')
key = decode(keyfile.readline(), 'hex')
key_decimal = int(key.hex(),16)
keyfile.close()

modulofile = open(sys.argv[3], 'rb')
modulo = decode(modulofile.readline(), 'hex')
modulo_decimal = int(modulo.hex(),16)
modulofile.close()

plaintext_prime = int(hex(fastpower(cipher_decimal, key_decimal, modulo_decimal)), 16)
outfile = open(sys.argv[4],'wb')
outfile.write(encode(hex(plaintext_prime)[2:]))
outfile.close()
