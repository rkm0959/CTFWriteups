from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
# from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random
import multiprocessing as mp
from Crypto.Util import Counter

x = 16158503035655503426113161923582139215996816729841729510388257123879913978158886398099119284865182008994209960822918533986492024494600106348146394391522057566608094710459034761239411826561975763233251722937911293380163746384471886598967490683174505277425790076708816190844068727460135370229854070720638780344789626637927699732624476246512446229279134683464388038627051524453190148083707025054101132463059634405171130015990728153311556498299145863647112326468089494225289395728401221863674961839497514512905495012562702779156196970731085339939466059770413224786385677222902726546438487688076765303358036256878804074494

CUTOFF = 10 ** 7
BITS = 2048
def factor(N, cand, k):
    print(k, len(cand))
    if len(cand) == 0:
        return None, None
    if len(cand) >= CUTOFF:
        return None, None
    ret = []
    for p, q in cand:
        if p * q == N:
            print(p, q)
            return p, q
        if k == BITS:
            continue
        # p * q == N mod 2^k
        cc = ((N - p * q) >> k) & 1
        for i in range(0, 2):
            for j in range(0, 2):
                if (i ^ j) == ((x >> k) & 1):
                    pp = p + (i << k)
                    qq = q + (j << k)
                    if (cc + i + j) & 1 == 0:
                        ret.append((pp, qq))
    return factor(N, ret, k+1)

sys.setrecursionlimit(10 ** 6)

f = open("public.pem", "r")
key = RSA.import_key(f.read())

n = key.n
e = key.e
f.close()

print(n.bit_length())
print(x.bit_length())

f = open("flag.enc", "rb")
S = f.read()
f.close()

p, q = factor(n, [(1, 1)], 1)
print(p, q)
d = inverse(e, (p-1) * (q-1))

key = RSA.construct((n, e, d, p, q))

cipher = PKCS1_OAEP.new(key)
print(cipher.decrypt(S))
