from sage.all import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import * 
import random as rand

'''
g^3 = (g+1)^3 mod p
3g^2 + 3g + 1 == 0 mod p

(g^3 x)^(x - g) * x + x^2 + g = U
((g+1)^3 x)^(x - (g + 1)) * x + x^2 + g + 1 = V 



(g^3x)^(x-g-1) = A


Ag^3x^2 + x^2 + g = U
Ax + x^2 + g + 1 = V


Ag^3x^2 + g^3x^3 + g^3(g+1) x = V g^3 x

U - x^2 - g + g^3 x^3 + g^3(g+1) x = Vg^3 x

'''


conn = remote("05.cr.yp.toc.tf", 37377)

g1 = 148789163573939977035323647523420
p1 = 66414645591098000760171453412624062238880692611047553669288059461

g2 = 108023421331938729600919893653772
p2 = 35007178668772666133861950583838008499139613997498752760310445269

G = [g1, g2]
P = [p1, p2]

queriesG = [g1, g1 + 1, g2, g2 + 1]
queriesP = [p1, p1, p2, p2]

results = []

for i in range(4):
    print(conn.recvline())

for i in range(4):
    print(conn.recvline())
    print(conn.recvline())
    print(conn.recvline())
    conn.sendline(b"s")
    print(conn.recvline())
    conn.sendline(str(queriesP[i]).encode())
    print(conn.recvline())
    conn.sendline(str(queriesG[i]).encode())
    result = int(conn.recvline().split()[-1])
    results.append(result)

roots = []
for i in range(2):
    POL = PolynomialRing(GF(P[i]), 'x')
    x = POL.gen()
    f = results[2 * i] - x * x - G[i] + (G[i] ** 3) * (x ** 3) + (G[i] ** 3) * (G[i] + 1) * x - results[2 * i + 1] * G[i] * G[i] * G[i] * x
    roots.append(f.roots())

for root1, _ in roots[0]:
    for root2, _ in roots[1]:
        sol = crt(int(root1), int(root2), p1, p2)
        print(long_to_bytes(int(sol)))


'''



flag = rand.randint(1 << 200, 1 << 202)
print(flag)

g = 0
p = 0
while True:
    g = rand.randint(1 << 105, 1 << 107)
    p = 3 * g * g + 3 * g + 1 
    if isPrime(p):
        break

print(g)
print(p)

result1 = (pow(g ** 3 * flag, flag - g, p) * flag + flag * flag + g) % p
result2 = (pow((g+1) ** 3 * flag, flag - (g + 1), p) * flag + flag * flag + (g + 1)) % p 


# U - x^2 - g + g^3 x^3 + g^3(g+1) x = Vg^3 x

P = PolynomialRing(GF(p), 'x')
x = P.gen()

f = result1 - x * x - g + (g ** 3) * (x ** 3) + (g ** 3) * (g + 1) * x - result2 * g * g * g * x

print(f.roots())


'''