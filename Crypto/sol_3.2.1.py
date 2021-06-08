import sys
from pymd5 import md5,padding
from urllib.parse import quote_from_bytes
from codecs import decode
def bruteforce_md5(state,query,secret_len):
    try:
        pad = padding((secret_len+len(query))*8)
        h = md5(state=state, count=512)
        return h,pad
    except:
        pass

if len(sys.argv) < 4:
    print('error: need 3 arguments.')
    exit()
query_fp = open(sys.argv[1], 'r')
cmd3_fp = open(sys.argv[2], 'r')
out_fp = open(sys.argv[3], 'w')

query = query_fp.readline()
query_old = query
cmd3 = cmd3_fp.readline()
query_fp.close()
cmd3_fp.close()

query_args =  query.split('&')
token = query_args[0]
token = token[token.index('=')+1:]
param = "".join([e for e in (query_args[1]+'&',query_args[2]+'&',query_args[3])])
# We know password is 8 charachters
hh,padded = bruteforce_md5(decode(token,'hex'),param,8)
hh.update(cmd3)

exploit='token='+hh.hexdigest()+'&'+param+quote_from_bytes(padded)+cmd3
out_fp.write(exploit)
out_fp.close()





## Test cases ####
secret='aaaaaaaa'
test_case = secret+param
h2 = md5(test_case.encode())
h3,pad = bruteforce_md5(decode(h2.hexdigest(),'hex'), param,8)
h3.update(cmd3)

# Check that MD5 hash of new state = MD5 hash of (m + padding(len(m)*8)+x)
h4 = md5(test_case.encode()+padding(len(test_case)*8) +cmd3.encode())
print('Test case: secret=%s'%(secret))
print('Expected hash: %s'%(h4.hexdigest()))
print('Length extension hash: %s'%(h3.hexdigest()))

## Test cases ####
secret='acju(-_z'
test_case = secret+param
h2 = md5(test_case.encode())
h3,pad = bruteforce_md5(decode(h2.hexdigest(),'hex'), param,8)
h3.update(cmd3)
h4 = md5(test_case.encode()+padding(len(test_case)*8) +cmd3.encode())
print('Test case: secret=%s'%(secret))
print('Expected hash: %s'%(h4.hexdigest()))
print('Length extension hash: %s'%(h3.hexdigest()))

