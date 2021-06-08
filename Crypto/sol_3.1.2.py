import sys
def main():
    if len(sys.argv) < 4:
        print('error: need 3 arguments')
        return -1
    ciphertext = open(sys.argv[1],'r')
    sub_lut = open(sys.argv[2],'r')
    outfile = open(sys.argv[3],'w')
    cipher = ciphertext.readline().encode()
    ciphertext.close()
    key_lut = sub_lut.readline().encode()
    sub_lut.close()
    soln =''
    lut = {}
    for i in range(len(key_lut)):
        lut[chr(key_lut[i])] = chr(0x41+i)
    for i in range(len(cipher)):
        encrypted_c = chr(cipher[i])#.decode()
        if encrypted_c == ' ' or encrypted_c.isnumeric():
            soln += encrypted_c
        else: 
            soln += lut[encrypted_c]
    outfile.write(soln)
    outfile.close()
main()
