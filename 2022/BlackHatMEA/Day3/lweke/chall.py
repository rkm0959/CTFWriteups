#!/usr/local/bin/python
#
# Polymero
#

# Imports
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from secrets import randbelow
from sympy import prevprime
import os, base64, hashlib

# Local imports
FLAG = os.environ.get('FLAG', 'flag{spl4t_th3m_bugs}').encode()


# Math functions
def gen_vec(N):
    return [randbelow(N) - N // 2 for _ in range(N)]

def gen_mat(N, Q):
    return [[randbelow(Q) for _ in range(N)] for _ in range(N)]

def mat_add(A, B, Q, a=1, b=1, c=0):
    return [[(a * A[i][j] + b * B[i][j] + c) % Q for j in range(len(B))] for i in range(len(A))]

def mat_mul(A, B, Q, c=1):
    return [[sum((c * A[i][j] * B[j][k]) % Q for j in range(len(B))) % Q for k in range(len(A))] for i in range(len(A))]

def mat_dia(A, B, Q, c=1):
    return [sum((c * A[i][j] * B[j][i]) % Q for j in range(len(B))) % Q for i in range(len(A))]

# Encoding functions
def enc_mat(A):
    byt = b"".join(bytes.fromhex(''.join('{:07x}'.format(j) for j in i)) for i in A)
    return base64.urlsafe_b64encode(byt).decode()

def dec_mat(A):
    hx = base64.urlsafe_b64decode(A).hex()
    rs = [hx[i:i + 7*128] for i in range(0, len(hx), 7*128)]
    return [[int(i[j:j + 7], 16) for j in range(0, len(i), 7)] for i in rs]

def enc_sig(s):
    return int(''.join(str(i) for i in s),2).to_bytes(128//8, 'big').hex()

# Crypto class
class LWEKE:
    def __init__(self, bit_sec, M=None, sk=None):
        self.N = bit_sec
        self.Q = prevprime(bit_sec**4)
        
        if M:
            assert len(M) == len(M[0]) == self.N
        else:
            M = gen_mat(self.N, self.Q)
        self.M = M
        
        if sk:
            assert len(sk) == self.N
        else:
            sk = [[i] * self.N for i in gen_vec(self.N)]
        self.sk = sk
        
    def signal(self, vec):
        out = []
        for i in vec:
            b = randbelow(2)
            out += [1 ^ (i > (self.Q - (self.Q//4) + b) or i < (-(-self.Q//4) + b))]
        return out
    
    def extract(self, vec, sig):
        return [((i + j * ((self.Q - 1) // 2)) % self.Q) & 1 for i,j in zip(vec, sig)]
    
    def initiate_handshake(self):
        eA = [gen_vec(self.N) for _ in range(self.N)]
        pA = mat_add(mat_mul(self.M, self.sk, self.Q), eA, self.Q, b=2)
        return pA
    
    def receive_handshake(self, pA):
        eB = [gen_vec(self.N) for _ in range(self.N)]
        pB = mat_add(mat_mul(list(zip(*self.M)), self.sk, self.Q), eB, self.Q, b=2)
        kB = mat_dia(list(zip(*pA)), self.sk, self.Q)
        sg = self.signal(kB)
        # pB = M^T * sk + 2 * eB
        # pB[i][j] - 128 <= M^T * sk [i][j] < pB[i][j] + 128
        shared = self.extract(kB, sg)
        secret = sum(shared[-1 - i] * 2**i for i in range(len(shared))).to_bytes(-(-self.N//8), 'big')
        return (pB, sg), secret
    
    def complete_handshake(self, pB, sg):
        kA = mat_dia(list(zip(*self.sk)), pB, self.Q)
        shared = self.extract(kA, sg)
        secret = sum(shared[-1 - i] * 2**i for i in range(len(shared))).to_bytes(-(-self.N//8), 'big')
        return secret
    
    
# Server loop
HDR = """|\n|\n|
|    â–„â–ˆ        â–„â–ˆ     â–ˆâ–„     â–„â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ    â–„â–ˆ   â–„â–ˆâ–„    â–„â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ
|   â–ˆâ–ˆâ–ˆ       â–ˆâ–ˆâ–ˆ     â–ˆâ–ˆâ–ˆ   â–ˆâ–ˆâ–ˆ    â–ˆâ–ˆâ–ˆ   â–ˆâ–ˆâ–ˆ â–„â–ˆâ–ˆâ–ˆâ–€   â–ˆâ–ˆâ–ˆ    â–ˆâ–ˆâ–ˆ
|   â–ˆâ–ˆâ–ˆ       â–ˆâ–ˆâ–ˆ     â–ˆâ–ˆâ–ˆ   â–ˆâ–ˆâ–ˆ    â–ˆâ–€    â–ˆâ–ˆâ–ˆâ–â–ˆâ–ˆâ–€     â–ˆâ–ˆâ–ˆ    â–ˆâ–€
|   â–ˆâ–ˆâ–ˆ       â–ˆâ–ˆâ–ˆ     â–ˆâ–ˆâ–ˆ  â–„â–ˆâ–ˆâ–ˆâ–„â–„â–„      â–„â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–€     â–„â–ˆâ–ˆâ–ˆâ–„â–„â–„
|   â–ˆâ–ˆâ–ˆ       â–ˆâ–ˆâ–ˆ     â–ˆâ–ˆâ–ˆ â–€â–€â–ˆâ–ˆâ–ˆâ–€â–€â–€     â–€â–€â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–„    â–€â–€â–ˆâ–ˆâ–ˆâ–€â–€â–€
|   â–ˆâ–ˆâ–ˆ       â–ˆâ–ˆâ–ˆ     â–ˆâ–ˆâ–ˆ   â–ˆâ–ˆâ–ˆ    â–ˆâ–„    â–ˆâ–ˆâ–ˆâ–â–ˆâ–ˆâ–„     â–ˆâ–ˆâ–ˆ    â–ˆâ–„
|   â–ˆâ–ˆâ–ˆâ–Œ    â–„ â–ˆâ–ˆâ–ˆ â–„â–ˆâ–„ â–ˆâ–ˆâ–ˆ   â–ˆâ–ˆâ–ˆ    â–ˆâ–ˆâ–ˆ   â–ˆâ–ˆâ–ˆ â–€â–ˆâ–ˆâ–ˆâ–„   â–ˆâ–ˆâ–ˆ    â–ˆâ–ˆâ–ˆ
|   â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–„â–„â–ˆâ–ˆ  â–€â–ˆâ–ˆâ–ˆâ–€â–ˆâ–ˆâ–ˆâ–€    â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ   â–ˆâ–ˆâ–ˆ   â–€â–ˆâ–€   â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ
|   â–€                                    â–€
|"""
print(HDR)

Server = LWEKE(128)

print('|  ~ Here is the domain parameter ::')
print('|    M = {}'.format(enc_mat(Server.M)))

key = hashlib.sha256(str(Server.sk).encode()).digest()
riv = os.urandom(16)
enc = riv + AES.new(key, AES.MODE_CBC, riv).encrypt(pad(FLAG, 16))

print('|\n|  ~ Here is the flag ::')
print('|    F = {}'.format(enc.hex()))

print('|  ~ Let us shake some hands, shall we?')
while True:
    
    try:
        
        print('|\n|  ~ Send me your public key for a handshake')
        pA = ''
        while len(pA) < 76460:
            pA += input('|  > (b64 {:.1f}/74.7KB) '.format(len(pA) / 1024))
        pA = dec_mat(pA)
        
        pB_sig, secret = Server.receive_handshake(pA)
        pB, sig = pB_sig
        
        tag = AES.new(secret, AES.MODE_ECB).encrypt(pad(b"Did it work?", 16))
        
        print('|\n|  ~ Here is my part ::')
        print('|    pB = {}'.format(enc_mat(pB)))
        print('|    sig = {}'.format(enc_sig(sig)))
        print('|    tag = {}'.format(tag.hex()))
        
    except KeyboardInterrupt:
        print('\n|  ~ Shake you later\n|') 
        break
        
    except:
        print('|\n|  ~ You okay there?\n|')