#!/usr/local/bin/python
#
# Polymero
#

# Imports
from Crypto.Util.number import inverse
from secrets import randbelow
from hashlib import sha256
import os, base64

# Local imports
FLAG = os.environ.get('FLAG', "flag{spl4t_th3m_bugs}").encode()


# Curve 25519 :: By^2 = x^3 + Ax^2 + x  mod P 
P = 2**255 - 19
A = 486662
B = 1
O = 7237005577332262213973186563042994240857116359379907606001950938285454250989


# ECC Class
class Point:
    def __init__(self, x, y=None):
        self.x = x
        if y:
            self.y = y
        else:
            self.y = self.__class__.lift_x(x)
            
        if not self.is_on_curve():
            raise ValueError("Point NOT on Curve 25519!")
        
    def is_on_curve(self):
        if self.x == 0 and self.y == 1:
            return True
        if ((self.x**3 + A * self.x**2 + self.x) % P) == ((B * self.y**2) % P):
            return True
        return False
    
    @staticmethod
    def lift_x(x):
        y_sqr = ((x**3 + A * x**2 + x) * inverse(B, P)) % P
        v = pow(2 * y_sqr, (P - 5) // 8, P)
        i = (2 * y_sqr * v**2) % P
        return Point(x, (y_sqr * v * (1 - i)) % P)
    
    def __repr__(self):
        return "Point ({}, {}) on Curve 25519".format(self.x, self.y)
    
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
        
    def __add__(self, other):
        if self == self.__class__(0, 1):
            return other
        if other == self.__class__(0, 1):
            return self
        
        if self.x == other.x and self.y != other.y:
            return self.__class__(0, 1)
        
        if self.x != other.x:
            l = ((other.y - self.y) * inverse(other.x - self.x, P)) % P
        else:
            l = ((3 * self.x**2 + 2 * A * self.x + 1) * inverse(2 * self.y, P)) % P
            
        x3 = (l**2 - A - self.x - other.x) % P
        y3 = (l * (self.x - x3) - self.y) % P
        return self.__class__(x3, y3)
    
    def __rmul__(self, k):
        out = self.__class__(0, 1)
        tmp = self.__class__(self.x, self.y)
        while k:
            if k & 1:
                out += tmp
            tmp += tmp
            k >>= 1
        return out

G = Point.lift_x(9)


# Crypto Class
class ECPC:
    def __init__(self):
        self.sk = randbelow(O)
        self.pk = self.sk * G
        self.id = sha256(str(self.pk).encode()).hexdigest()
        
    def pub_hash(self, m: bytes):
        return int.from_bytes(sha256(str(self.pk).encode() + m).digest(), 'big')
    
    def ecdsa_sign(self, m: bytes):
        h = self.pub_hash(m)
        k = randbelow(O)
        r = (k * G).x % O
        s = (inverse(k, O) * (h + r * self.sk)) % O
        return (r, s)
    
    def ecdsa_verify(self, m, sig):
        r, s = sig
        if r > 0 and r < O and s > 0 and s < O:
            h = self.pub_hash(m)
            u1 = (h * inverse(s, O)) % O
            u2 = (r * inverse(s, O)) % O
            if r == (u1 * G + u2 * self.pk).x % O:
                return True
        return False

    def encrypt(self, m):
        out = b""
        for bit in '{:0{n}b}'.format(int.from_bytes(m, 'big'), n=len(m)*8):
            if bit == '1':
                r, s = self.ecdsa_sign(bit.encode())
            else:
                r, s = randbelow(O), randbelow(O)
            out += b"".join(base64.urlsafe_b64encode(i.to_bytes(32, 'big')).rstrip(b"=") for i in (r, s))
        return out



# Challenge setup
HDR = r"""|
|    _____________  
|   |  _____  ____| 
|   | |__  | |      
|   |  __| | |      
|   | |____| |____  
|   |     __\     | 
|   |  __ \_/ ____|
|   | |__)   |     
|   |  ___/| |     
|   | |    | |____ 
|   |_|     \_____|               
|"""
print(HDR)

ecpc = ECPC()

print('|\n|  ~ Welcome to our ECPC service ::')
print('|    Connection_ID = {}'.format(ecpc.pub_hash(b'')))

enc_flag = ecpc.encrypt(FLAG).decode()
print('|\n|  ~ Here is a little gift ::')
print('|    Encrypted_Flag = {}'.format(enc_flag))

print('|\n|  ~ Initiating signing service ::')


# Server loop
while True:

	try:

		msg = bytes.fromhex(input("|\n|  > (hex) "))

		print('|\n|  ~ Signature ::')
		print('|    (r, s) = {}'.format(ecpc.ecdsa_sign(msg)))

	except KeyboardInterrupt:
		print("\n|  ~ C you later.\n|")
		break

	except:
		print("|\n|  ~ Take it EC will you?")