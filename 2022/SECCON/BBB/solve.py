from Crypto.Util.number import *
from pwn import *
from sage.all import *

conn = remote("BBB.seccon.games", 8080)

print(conn.recvline())
a = int(conn.recvline()[2:])
p = int(conn.recvline()[2:])

b = (11 - 11 * 11 - a * 11) % p 

conn.sendline(str(b).encode())



POL = PolynomialRing(GF(p), 'x')
x = POL.gen()

conn.sendline(b"11")
seeds = []

target = 11
seeds.append(11)

from tqdm import tqdm

for i in tqdm(range(4)):
    f = x * x + a * x + b - target 
    tt = f.roots()
    for (rt, mul) in tt:
        print(i, rt)
        if int(rt) not in seeds:
            print("hi?")
            print(rt)
            seeds.append(int(rt))
            target = int(rt)
            conn.sendline(str(rt).encode())
            break 

for i in range(20):
    print(conn.recvline())