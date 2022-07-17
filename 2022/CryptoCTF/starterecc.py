from sage.all import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, inverse, getPrime
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from pwn import * 
import random as rand
from tqdm import tqdm
import requests
import json
from hashlib import sha256
from base64 import b64encode
import time 

x = 10715086071862673209484250490600018105614048117055336074437503883703510511249361224931983788156958581275946729175531468251871452856923140435984577574698574803934567774824230985421074605062371141877954182153046477020617917601884853827611232355455223966039590143622792803800879186033924150173912925208583
a = 31337
b = 66826418568487077181425396984743905464189470072466833884636947306507380342362386488703702812673327367379386970252278963682939080502468506452884260534949120967338532068983307061363686987539408216644249718950365322078643067666802845720939111758309026343239779555536517718292754561631504560989926785152983649035
n = 117224988229627436482659673624324558461989737163733991529810987781450160688540001366778824245275287757373389887319739241684244545745583212512813949172078079042775825145312900017512660931667853567060810331541927568102860039898116182248597291899498790518105909390331098630690977858767670061026931938152924839936


ps = [2, 690712633549859897233, 651132262883189171676209466993073]
es = [63, 6, 5]

bb = [ps[i] ** es[i] for i in range(3)]

assert n == bb[0] * bb[1] * bb[2]

target = (x * x * x + a * x + b) % n 

sol = [[] for _ in range(3)]

d = 63
vv = [1, 3, 5, 7]

for i in range(4, 64):
    nxt = []
    for j in vv:
        for t in range(4):
            c1 = j + t * (2 ** (i - 2))
            if (c1 * c1) % (1 << i) == target % (2 ** i):
                nxt.append(c1 % (1 << i))
    vv = list(set(nxt))

print(len(vv))

for x in vv:
    assert (x * x) % (1 << 63) == (target) % (1 << 63)

sol[0] = vv 

P = PolynomialRing(GF(ps[1]), 'x')
x = P.gen()
f = x * x - int(target)

solp1 = int(int(f.roots()[0][0]) % ps[1])

for i in range(2, 7):
    # (x+kp^(i-1))^2 == x^2 + 2xkp^(i-1) == target mod p^i
    res = (target - solp1 * solp1) // (ps[1] ** (i - 1))
    # 2xk == res mod p 
    k = (res * inverse(2 * solp1, ps[1])) % ps[1] 
    solp1 += int(k) * int(ps[1] ** (i - 1))

sol[1] = [solp1, ps[1] ** 6 - solp1]

assert (sol[1][0] ** 2 - target) % bb[1] == 0

P = PolynomialRing(GF(ps[2]), 'x')
x = P.gen()
f = x * x - int(target)

solp2 = int(f.roots()[0][0]) % ps[2]

for i in range(2, 6):
    # (x+kp)^2 == x^2 + 2xkp  == target mod p^2 
    res = (target - solp2 * solp2) // (ps[2] ** (i - 1))
    # 2xk == res mod p 
    k = (res * inverse(2 * solp2, ps[2])) % ps[2] 
    solp2 += k * (ps[2] ** (i - 1))

sol[2] = [solp2, ps[2] ** 5 - solp2]

assert (sol[2][0] ** 2 - target) % bb[2] == 0

for u in sol[0]:
    for v in sol[1]:
        for w in sol[2]:
            ans = crt([u, v, w], bb)
            print((ans * ans - target) % n)
            flag = long_to_bytes(ans)
            print(flag)


