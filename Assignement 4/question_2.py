# use "pip install pyprimes" if pyprimes is not installed
# use "pip install pycryptodome" if pycryptodome is not installed
import math
import timeit
import random
import sympy
import warnings
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA3_384
from Crypto.Hash import SHA3_512
from Crypto.Hash import SHAKE128, SHAKE256

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def random_prime(bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while chck == False:
        p = random.randrange(2**(bitsize-1), 2**(bitsize)-1)
        chck = sympy.isprime(p)
    warnings.simplefilter('default')    
    return p
 
k0 = 8
k1 = 128

def RSA_KeyGen(bitsize):
    p = random_prime(bitsize)
    q = random_prime(bitsize)
    N = p*q
    phi_N = (p-1)*(q-1)
    e = 2**16+1
    while True:
        gcd, x, y = egcd(e, phi_N)
        if gcd == 1:
            break
        e = e+2
    d = modinv(e, phi_N)    
    return e, d, p, q, N

def RSA_OAEP_Enc(m, e, N, R):
    k = N.bit_length()-2
    m0k1 = m << k1
    shake = SHAKE128.new(R.to_bytes(k0//8, byteorder='big'))
    GR =  shake.read((k-k0)//8)
    m0k1GR = m0k1 ^ int.from_bytes(GR, byteorder='big')
    shake = SHAKE128.new(m0k1GR.to_bytes((m0k1GR.bit_length()+7)//8, byteorder='big'))
    Hm0k1GR =  shake.read(k0//8)
    RHm0k1GR = R ^ int.from_bytes(Hm0k1GR, byteorder='big')
    m_ = (m0k1GR << k0) + RHm0k1GR
    c = pow(m_, e, N)
    return c

def RSA_OAEP_Dec(c, d, N):
    k = N.bit_length()-2
    m_ = pow(c, d, N)
    m0k1GR = m_ >> k0
    RHm0k1GR =  m_ % 2**k0
    shake = SHAKE128.new(m0k1GR.to_bytes((m0k1GR.bit_length()+7)//8, byteorder='big'))
    Hm0k1GR =  shake.read(k0//8)
    R = int.from_bytes(Hm0k1GR, byteorder='big') ^ RHm0k1GR
    shake = SHAKE128.new(R.to_bytes(k0//8, byteorder='big'))
    GR =  shake.read((k-k0)//8)
    m0k1 = m0k1GR ^ int.from_bytes(GR, byteorder='big')
    m = m0k1 >> k1
    return m

blen = 2048  # bit length of RSA modulus
e, d, p, q, N = RSA_KeyGen(blen//2)    # RSA key generate (p and q are selected at random)
print("p =", p)
print("q =", q)
print("N =", N)
print("e =", e)
print("d =", d)

print("\nTesting Encryption and Decryption Functions")
failure = 0
for i in range(0, 10):
    m = random.randint(0,10000)
    R =  random.randint(2**(k0-1), 2**k0-1)
    c = RSA_OAEP_Enc(m, e, N, R)
    if m != RSA_OAEP_Dec(c, d, N):
        failure += 1 
        
if failure != 0:
    print("Failure:(", failure)
else:
    print("Success:)")
    
c = 10874572375620617789377153154263475798901864318895755165739361956409713948425
e = 65537
N = 39011863995815647013266848060295512705184137160777355248310252490843225091289

# though it may take some time, we can use brute force to crack the code by encrypting each possible message in given 
#range with with using each possible R value for every m value

for m in range(1, 10000):
    for R in range(2**(k0-1), 2**k0-1):
        c_ = RSA_OAEP_Enc(m, e, N, R)
        if (c == c_):
            print("R = ", R)
            print("m = ", m)
            break
        
