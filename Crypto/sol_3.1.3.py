import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from codecs import decode
if len(sys.argv) < 5:
    print('error: need 4 arguments')
ciphertext = open(sys.argv[1],'rb')
cipher = decode(ciphertext.readline(),'hex')
ciphertext.close()
keyfile = open(sys.argv[2],'rb')
key = decode(keyfile.readline(),'hex')
keyfile.close()

ivfile = open(sys.argv[3],'rb')
iv = decode(ivfile.readline(),'hex')
ivfile.close()
outfile = open(sys.argv[4],'w')
aes = AES.new(key, AES.MODE_CBC, iv)
decrypted_msg = aes.decrypt(cipher)
outfile.write(decrypted_msg.decode())
outfile.close()
