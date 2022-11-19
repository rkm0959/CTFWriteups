#!/usr/local/bin/python
#
#

# Imports
from Crypto.Util.number import isPrime, getPrime, inverse
from secrets import randbelow
from sympy import nextprime
import hashlib, time, os

# Local import
FLAG = os.environ.get('FLAG', 'flag{spl4t_th3m_bugs}').encode()


class URSA:
    # Upgraded RSA (faster and with cheap key cycling)
    def __init__(self, pbit, lbit):
        p, q = self.prime_gen(pbit, lbit)
        self.public = {'n': p * q, 'e': 0x10001}
        self.private = {'p': p, 'q': q, 'f': (p - 1)*(q - 1), 'd': inverse(self.public['e'], (p - 1)*(q - 1))}
        
    def prime_gen(self, pbit, lbit):
        # Smooth primes are FAST primes ~ !
        B = 2**lbit
        while True:
            q, qlst = 1, []
            while q.bit_length() < pbit - 1:
                qlst += [nextprime(randbelow(min([B, 2**(pbit - q.bit_length())])))]
                q *= qlst[-1]
            if len(qlst) != len(set(qlst)):
                continue
            Q = 2 * q + 1
            if isPrime(Q):
                break
        while True:
            p, plst = 1, []
            while p.bit_length() < pbit - 1:
                plst += [nextprime(randbelow(min([B, 2**(pbit - p.bit_length())])))]
                p *= plst[-1]
            if len(plst) != len(set(plst)):
                continue
            if any(i in qlst for i in plst):
                continue
            P = 2 * p + 1
            if isPrime(P):
                break
        print("|\n|  ~ Here is a little hint for you ::", (len(plst), len(qlst)))
        return P, Q
    
    def update_key(self):
        # Prime generation is expensive, so we'll just update d and e instead ^w^
        self.public['e'] ^= int.from_bytes(hashlib.sha512((str(self.private['d']) + str(time.time())).encode()).digest(), 'big')
        self.public['e'] %= self.private['f']
        if not self.public['e'] & 1:
            self.public['e'] ^= 1
        self.private['d'] = inverse(self.public['e'], self.private['f'])
        
    def encrypt(self, m_int):
        c_lst = []
        while m_int:
            c_lst += [pow(m_int, self.public['e'], self.public['n'])]
            m_int //= self.public['n']
        return c_lst
    
    def decrypt(self, c_int):
        m_lst = []
        while c_int:
            m_lst += [pow(c_int, self.private['d'], self.public['n'])]
            c_int //= self.public['n']
        return m_lst


# Challenge setup
print("""|
|  ~ Welcome to URSA decryption services
|    Press enter to start key generation...""")

input("|")

print("""|
|    Please hold on while we generate your primes...
|\n|""")
    
PBIT, LBIT = 256, 12
oracle = URSA(PBIT, LBIT)
print("|\n|  ~ You are connected to an URSA-{}-{} service, public key ::".format(PBIT, LBIT))
print("|    id = {}".format(hashlib.sha256(str(oracle.public['n']).encode()).hexdigest()))
print("|    e  = {}".format(oracle.public['e']))

print("|\n|  ~ Here is a free flag sample, enjoy ::")
for i in oracle.encrypt(int.from_bytes(FLAG, 'big')):
    print("|    {}".format(i))


MENU = """|
|  ~ Menu ::
|    [E]ncrypt ({} left)
|    [D]ecrypt ({} left)
|    [U]pdate key
|    [Q]uit
|"""

# Server loop
ENC, DEC = False, False
while True:
    
    try:

        if ENC or DEC:
            print(MENU.format(int(ENC), int(DEC)))
            choice = input("|  > ")

        else:
            choice = 'u'
        
        if ENC and choice.lower() == 'e':
            msg = int(input("|\n|  > (int) ")) % oracle.public['n']

            print("|\n|  ~ Encryption ::")
            for i in oracle.encrypt(msg):
                print("|    {}".format(i))

            ENC = False

        elif DEC and choice.lower() == 'd':
            cip = int(input("|\n|  > (int) ")) % oracle.public['n']

            print("|\n|  ~ Decryption ::")
            for i in oracle.decrypt(cip):
                print("|    {}".format(i))

            DEC = False
            
        elif choice.lower() == 'u':
            oracle.update_key()
            print("|\n|  ~ Key updated succesfully ::")
            print("|    id = {}".format(hashlib.sha256(str(oracle.public['n']).encode()).hexdigest()))
            print("|    e  = {}".format(oracle.public['e']))

            ENC, DEC = True, True
            
        elif choice.lower() == 'q':
            print("|\n|  ~ Closing services...\n|")
            break
            
        else:
            print("|\n|  ~ ERROR - Invalid command")
        
    except KeyboardInterrupt:
        print("\n|  ~ Closing services...\n|")
        break
        
    except:
        print("|\n|  ~ Please do NOT abuse our services.\n|")