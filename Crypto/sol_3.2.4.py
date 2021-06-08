from Crypto.Util import number
from Crypto.PublicKey import RSA
import pbp
import copy
import numpy as np
import math

e = 65537

def get_d(p, q, e):
    totient = (p-1)*(q-1)
    return number.inverse(e, totient)

def gcd(a, b):
    if b == 0:
        return a

    return gcd(b, a % b)

"""
Inspirations/Sources: 
    https://facthacks.cr.yp.to/product.html
    https://courses.csail.mit.edu/6.857/2017/project/11.pdf
"""
def build_prodTree(moduli):
    tree = [moduli]
    temp = copy.deepcopy(moduli)
    while len(temp) > 1:
        newTemp = []
        for i in range(0, len(temp), 2):
            firstNumIdx = i
            secNumIdx = i+1
            
            val = 0
            if secNumIdx >= len(temp):
                val = temp[firstNumIdx]
            else:
                val = temp[firstNumIdx] * temp[secNumIdx]
    
            newTemp.append(val)

        temp = copy.deepcopy(newTemp)
        tree.append(temp)
    
    return tree

"""
Inspirations/Sources: 
    https://facthacks.cr.yp.to/remainder.html
    https://courses.csail.mit.edu/6.857/2017/project/11.pdf
"""
def build_remTree(prodTree):
    n = len(prodTree)
    product = prodTree[n-1][0]
    tree = [[product]]

    if n == 1:
        tree.insert(0, [product % product**2])
        return tree

    for i in range(n-2, -1, -1):
        higherRems = tree[0]
        currProds = prodTree[i]
        
        currProdsLen = len(currProds) 

        temp = []

        for j in range(currProdsLen):
            temp.append(higherRems[int(j/2)] % currProds[j]**2)

        tree.insert(0, temp)
    
    return tree

def gcd_finding(moduli):
    # For both trees, the root is the last value - the product of all moduli
    prodTree = build_prodTree(moduli)
    remTree = build_remTree(prodTree)

    # TODO: save prodTree and remTree
    n = len(moduli)

    pqs = []
    for i in range(n):
        modulus = moduli[i]
        rem = remTree[0][i] // modulus
        gcdVal = gcd(modulus, rem)
        if gcdVal > 1 and gcdVal < modulus:
            p = gcdVal
            q = modulus//gcdVal

            if gcd((p-1)*(q-1), e) == 1:
                pqs.append((p, q))

    return pqs

# Tests to make sure trees are built correctly
"""
print(build_prodTree([5]))
print(build_prodTree([5, 10]))
print(build_prodTree([5, 10, 8]))
print(build_prodTree([5, 10, 8, 2]))
print(build_prodTree([5, 10, 8, 2, 2]))

print(build_remTree(build_prodTree([5]))[0] == [5])
print(build_remTree(build_prodTree([5, 10]))[0] == [50 % val**2 for val in [5, 10]])
print(build_remTree(build_prodTree([5, 10, 8]))[0] == [400 % val**2 for val in [5, 10, 8]])

print(build_remTree(build_prodTree([5]))[0])
print(build_remTree(build_prodTree([5, 10]))[0])
print(build_remTree(build_prodTree([5, 10, 8]))[0])

print([5])
print([50 % val**2 for val in [5, 10]])
print([400 % val**2 for val in [5, 10, 8]])

print(build_remTree(build_prodTree([5, 10, 8, 2]))[0] == [800 % val**2 for val in [5, 10, 8, 2]])
print(build_remTree(build_prodTree([5, 10, 8, 2, 2]))[0] == [1600 % val**2 for val in [5, 10, 8, 2, 2]])
"""
# Turn encrypted file into a string, which will be the ciphertext
encryptedFile = open("3.2.4_ciphertext.enc.asc", "r")
ciphertext = encryptedFile.read()
encryptedFile.close()

# Transform hex strings of each modulus into an integer
moduliFile = open("moduli.hex", "r")
hexModuli = moduliFile.readlines()

moduli = []
n = len(hexModuli)
for i in range(n):
    moduli.append(int(hexModuli[i], 16))

# Find the gcds that we are asked to get
pqs = gcd_finding(moduli)
pqsLen = len(pqs)

# Get possible secret keys
secrets = []
for i in range(pqsLen):
    p = pqs[i][0]
    q = pqs[i][1]
    if p == 1 or q == 1:
        continue
    
    d = get_d(p, q, e)
    secrets.append((d, p, q))

# Convert all secret keys to a RSA key object through RSA.construction()
# Found in pbp file under decrypt
# Then call decrypt on current key and ciphertext
output = open("sol_3.2.4.txt", "w")

for secret in secrets:
    d = secret[0]
    p = secret[1]
    q = secret[2]
    n = p * q
    
    try:
        rsakey = RSA.construct((n, e, d))
        plaintext = pbp.decrypt(rsakey, ciphertext)
        plaintext = plaintext.decode('utf-8')
        print(plaintext)
        output.write(plaintext)
    except Exception:
        continue

output.close()
moduliFile.close()

