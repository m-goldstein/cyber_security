from Crypto.Util import number
import os
import signal
import sys
from codecs import decode
from codecs import encode
from hashlib import md5
import random
from mp3_certbuilder import make_privkey, make_cert

SEED = 'junk/'+str(random.randint(1,100))+'_'
def calc_b(b1_exp,b2_exp,b1,b2,big_b=False):

    flag = False
    new_primes = False

    p1 = number.getPrime(500)
    p2 = number.getPrime(500)
    b = 0
    k = 0
    if big_b == True:
        k = 2**25-1
    result = {}
    while flag == False: 
        #print('k: {}\t b bit length: {}'.format(k,b.bit_length()))
        if new_primes == True:
            p1 = number.getPrime(500)
            p2 = number.getPrime(500)
            k = 0
            if big_b == True:
                k = 2**25-1
            new_primes = False
        e = (p1-1)*(p2-1)+1
        b0 = getCRT(b1_exp,b2_exp,p1,p2)
        b = b0+k*p1*p2
        if b.bit_length() > 1024:
            print('err: b is too large.')
            new_primes = True
            continue
        q1 = (b1_exp+b)//p1
        q2 = (b2_exp+b)//p2
        k += 1
        if not (number.isPrime(q1) and number.isPrime(q2)) or not (is_coprime(e, p1-1) and is_coprime(e,p2-1)):
            pass
        else:
            print('passed check 1')
            if is_coprime(e,q1-1) and is_coprime(e,q2-1):
                print('passed check 2')
                if (b1*(2**1024)+b).bit_length() < 2047 or (b2*(2**1024)+b).bit_length() < 2047:
                    flag = False
                    continue
                else:
                    print('passed check 3')
                    if big_b == True:
                        if b.bit_length() == 1024:
                            print('passed check 4')
                            flag = True
                            break
                        else:
                            flag = False
                            continue
                    else:
                        flag = True
                        break
         
    result['n1'] = b1*(2**1024)+b
    result['n2'] = b2*(2**1024)+b
    result['p1'] = p1
    result['p2'] = p2
    result['q1'] = q1
    result['q2'] = q2
    result['b']  = b
    return result
def is_coprime(p1,p2):
    return (number.GCD(p1,p2) == 1)

def make_multiple_of_64(tbs):
    #totalLen = len(tbs) - 6
    copy = bytearray(tbs)
    num = len(tbs)%64
    numExtraBytesNeeded = 64-num
    print('got: {}b\tneed: {}b'.format(len(tbs),numExtraBytesNeeded))
    extra = b'\x41' * (numExtraBytesNeeded+6)
    ret = bytes(copy.replace(b"unused", extra))
    return ret

def fastpower(c,d):
    if d == 0:
        return 1
    elif d == 1:
        return c
    else:
        k = fastpower(c,d//2)
        if not (d&1):
            return (k*k)
        else:
            return (k*k*c)
    return 0

def make_fastcolls(fname, idx):
    col1 = ''
    col2 = ''

    m = 0
    n = 0
    i = 0
    str1 = ''
    str2 = ''
    while (m != 1023 or n != 1023):
        os.system("./fastcoll -p {} -o {}col1 {}col2".format(fname,SEED,SEED))

        f1 = open("{}col1".format(SEED), "rb")
        f2 = open("{}col2".format(SEED), "rb")

        str1 = f1.read()[idx:]
        str2 = f2.read()[idx:]

        col1 = int(str1.hex(), 16)
        col2 = int(str2.hex(), 16)

        m = number.size(col1)
        n = number.size(col2)
        print('m={}\nn={}'.format(m,n))

        f1.close()
        f2.close()
    #col1_stream = open('{}col1_stream'.format(SEED),'wb')
    #col2_stream = open('{}col2_stream'.format(SEED),'wb')
    print('writing bitstreams to file\n stream1: {}\nstream2: {}'.format(encode(str1,'hex').decode(),encode(str2,'hex').decode()))
    #col1_stream.write(decode(hex(col1)[2:],'hex'))#hex(col1)[2:].encode())
    #col2_stream.write(decode(hex(col2)[2:],'hex'))#hex(col2)[2:].encode())
    #col1_stream.write(str1)#str(int(str1,16)))#encode(str1,'hex'))
    #col2_stream.write(str2)#str(int(str2,16)))#encode(str2,'hex'))
    #col1_stream.close()
    #col2_stream.close()

    #col1_fp = open("{}col1".format(SEED), "rb")
    #col2_fp = open("{}col2".format(SEED), "rb")
    #col1 = col1_fp.read()
    #col2 = col2_fp.read()
    #print('md5 of col1:{}\nmd5 of col2:{}'.format(md5(col1).hexdigest(),md5(col2).hexdigest()))#md5(decode(hex(col1)[2:].encode(),'hex')).hexdigest(),md5(decode(hex(col2)[2:].encode(),'hex')).hexdigest()))
    #col1 = int(encode(col1, 'hex'),16)
    #col2 = int(encode(col2, 'hex'),16)
    return col1, col2

def getCRT(b1_exp,b2_exp,p1,p2):
    N = p1*p2
    invOne = number.inverse(p2,p1)
    invTwo = number.inverse(p1,p2)
    return -(b1_exp*invOne*p2 + b2_exp*invTwo*p1)%N
# Used to find a certificate with a 2047 bit key
# NOTE: Comment out everything from tbs_cert_bytes to the end when running this little portion to get your tbs_cert_bytes and the modulus in hex
# NOTE: Make sure that you have created 3.2.5_certificate.txt ahead of time
# NOTE: Replace my net id with your netid
#f = open("{}3.2.5_certificate.txt".format(SEED), "r")
#certificate = f.read()
#f.close()

#while certificate.find("(2047 bit)") == -1:
#while True:
#    os.system("python3 mp3_certbuilder.py mgg2 {}3.2.5_certificate.cer".format(SEED))
#    os.system("openssl x509 -in {}3.2.5_certificate.cer -inform der -text -noout > {}3.2.5_certificate.txt".format(SEED,SEED))
#    f = open("{}3.2.5_certificate.txt".format(SEED), "r")
#    certificate = f.read()
#    f.close()
#    serial_num = int(certificate[56+27:56+27+59].replace(':',''),16)
#    break
# NOTE: Edit mp3-certbuilder.py to print out cert.tbs_cert_bytes and modulus as hex. Then copy and paste them here. Assign them to their respective variables below.
#cert_fp = open('{}3.2.5_certificate.cer'.format(SEED),'rb')

_p = number.getPrime(1024)
_q = number.getPrime(1024)
_sk,_pk = make_privkey(_p,_q)
_cert = make_cert('mgg2',_pk)
tbs_cert_bytes = _cert.tbs_certificate_bytes
#tbs_cert_bytes = make_multiple_of_64(tbs_cert_bytes)
modulo_bytes = decode(hex(_pk.public_numbers().n)[2:].encode(), 'hex')
modulo_start_idx = tbs_cert_bytes.find(modulo_bytes)
#trimmed_tbs = #tbs_cert_bytes[:modulo_start_idx]
trimmed_tbs = make_multiple_of_64(tbs_cert_bytes[:modulo_start_idx])
modulo_start_idx = len(trimmed_tbs)
#orig_cert = cert_fp.readlines()
#orig_cert = b''.join(e for e in orig_cert)
#fp = open('{}cert_builder_out'.format(SEED),'rb')
#lines = fp.readlines()
#fp.close()
#lines[0] = lines[0][:-1]
#tbs_cert_bytes = decode(lines[0],'hex')
#modulusHex = lines[1]

#bytesModulus = decode(modulusHex,'hex')#bytes.fromhex(modulusHex)
#startOfModulusByte = encode(tbs_cert_bytes,'hex').find(lines[1])#bytesModulus)
#startOfModulusByte //=2
#print('start of modulus byte: {}'.format(startOfModulusByte))
# The prefix that we want
#trimmedTBSCertBytes = tbs_cert_bytes[:startOfModulusByte]
#trimmedTBSCertBytes = make_multiple_of_64(trimmedTBSCertBytes)
#newLen = len(trimmedTBSCertBytes)

#startOfModulusByte = newLen#len(tbs_cert_bytes)-(startOfModulusByte)+1

prefixFname = "{}3.2.5_prefix".format(SEED)
prefix = open(prefixFname, "wb")
#prefix.write(
prefix.write(trimmed_tbs)
prefix.close()

# Make fastcolls to get bit strings of length 1023 that cause prefix concatenated with these strings to have a md5 collision
col1, col2 = make_fastcolls(prefixFname, modulo_start_idx)

#s1 = open('{}col1_stream'.format(SEED),'rb')
#s2 = open('{}col2_stream'.format(SEED),'rb')
#stream1 = (s1.read())#b''.join(e for e in s1.readlines())#int(s1.readline(),16)
#stream2 = (s2.read())#b''.join(e for e in s2.readlines())#int(s2.readline(),16)
#s1.close()
#s2.close()

#print('md5 of stream1: {}\nmd5 of stream2: {}'.format(md5(stream1).hexdigest(),md5(stream2).hexdigest()))
#p = number.getPrime(1024)
#q = number.getPrime(1024)
#sk,pk = make_privkey(p,q)
#cert = make_cert('mgg2',pk)
#b1 = int(encode(stream1,'hex'),16)#col1#int(stream1.hex(), 16)
#b2 = int(encode(stream2,'hex'),16)#col2#int(stream2.hex(), 16)
b1 = col1
b2 = col2
print('b1 bit length: {}\nb2 bit length: {}'.format(b1.bit_length(),b2.bit_length()))

#x = input()
b1_exp = b1*(2**1024)
b2_exp = b2*(2**1024)
big_b = False
if len(sys.argv) > 1:
        big_b = True
res = calc_b(b1_exp,b2_exp,b1,b2,big_b=big_b)
fp1 = open('{}sol_3.2.5_factorsA.hex'.format(SEED),'w')
fp1.writelines([hex(res['n1'])[2:]+'\n',hex(res['p1'])[2:]+'\n',hex(res['q1'])[2:]+'\n'])
fp2 = open('{}sol_3.2.5_factorsB_.hex'.format(SEED),'w')
fp2.writelines([hex(res['n2'])[2:]+'\n',hex(res['p2'])[2:]+'\n',hex(res['q2'])[2:]+'\n'])
fp1.close()
fp2.close()
c1 = decode(hex(col1)[2:],'hex')+decode(hex(res['n1'])[2:],'hex')
c2 = decode(hex(col2)[2:],'hex')+decode(hex(res['n2'])[2:],'hex')
col1_fp = open('{}col1'.format(SEED),'ab')
col2_fp = open('{}col2'.format(SEED),'ab')
col1_fp.write(decode(hex(res['n1'])[2:], 'hex'))
col2_fp.write(decode(hex(res['n1'])[2:], 'hex'))
col1_fp.close()
col2_fp.close()
from mp3_certbuilder import make_privkey
from mp3_certbuilder import make_cert
from cryptography.hazmat.primitives.serialization import Encoding
import copy
e = (res['p1']-1)*(res['p2']-1)+1
sk_A,pk_A = make_privkey(res['p1'],res['q1'],e,n=res['n1'])
sk_B,pk_B = make_privkey(res['p2'],res['q2'],e,n=res['n2'])
n1_bytes = decode(hex(res['n1'])[2:], 'hex')
n2_bytes = decode(hex(res['n2'])[2:], 'hex')
certA = make_cert('mgg2', pk_A, serial=_cert.serial_number)
certB = make_cert('mgg2', pk_B, serial=_cert.serial_number)
certA_bytes = bytearray(certA.public_bytes(Encoding.DER))
certB_bytes = bytearray(certA.public_bytes(Encoding.DER))
certA_bytes = certA_bytes.replace(certA.signature, _cert.signature)
certB_bytes = certB_bytes.replace(certB.signature, _cert.signature)
old_modulus_A = decode(encode(certA_bytes,'hex')[398:910],'hex')
old_modulus_B = decode(encode(certB_bytes,'hex')[398:910],'hex')
new_modulus_A = n1_bytes #decode(hex(res['p1']*res['q1'])[2:],'hex')
new_modulus_B = n2_bytes #decode(hex(res['p2']*res['q2'])[2:],'hex')
#certA_bytes = bytearray(_cert.public_bytes(Encoding.DER))
#certB_bytes = bytearray(_cert.public_bytes(Encoding.DER))
#certA_bytes = certA_bytes.replace(certA.tbs_certificate_bytes,tbs_cert_bytes)
#certB_bytes = certB_bytes.replace(certA.tbs_certificate_bytes,tbs_cert_bytes)
#certA_bytes = certA_bytes.replace(b'unused',b'AA')#make_multiple_of_64(tbs_cert_bytes[:modulo_start_idx])
#certB_bytes = certB_bytes.replace(b'unused',b'AA')
# if all goes well, the modulus starts at byte 398 and goes until byte 910 for a length of 512
#certA_bytes = certA_bytes.replace(old_modulus_A, new_modulus_A)
#certB_bytes = certB_bytes.replace(old_modulus_A, new_modulus_B)
#modulus_idx_A = certA_bytes.index(old_modulus_A)
#modulus_idx_B = certB_bytes.index(old_modulus_A)
#modulus_idx_A_end = modulus_idx_A+len(old_modulus_A)
#modulus_idx_B_end = modulus_idx_B+len(old_modulus_A)

#certA_bytes[modulus_idx_A:modulus_idx_A_end] = new_modulus_A
#certB_bytes[modulus_idx_B:modulus_idx_B_end] = new_modulus_B
print('certA modulus: {}\ncertB modulus: {}'.format(encode(certA_bytes,'hex')[398:910],encode(certB_bytes,'hex')[398:910]))
certA_bytes = bytes(certA_bytes)
certB_bytes = bytes(certB_bytes)
certA_fname = '{}certA.cer'.format(SEED)
certB_fname = '{}certB.cer'.format(SEED)
certA_fp = open(certA_fname,'wb')
certB_fp = open(certB_fname,'wb')

certA_fp.write(certA_bytes)
certB_fp.write(certB_bytes)
certA_fp.close()
certB_fp.close()

hexdigest1 = md5(certA_bytes[4:4+len(tbs_cert_bytes)]).hexdigest()
hexdigest2 = md5(certB_bytes[4:4+len(tbs_cert_bytes)]).hexdigest()
print('md5 of certA: {}\nmd5 of certB: {}'.format(hexdigest1,hexdigest2))
print('certA contents:')
print('{}'.format(os.system('openssl x509 -in {} -inform der -text -noout'.format(certA_fname))))
print('certB contents:')
print('{}'.format(os.system('openssl x509 -in {} -inform der -text -noout'.format(certB_fname))))
if (hexdigest1 == hexdigest2):
    print('Success!')
else:
    print('Nope!')
