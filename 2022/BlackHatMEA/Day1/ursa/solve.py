from pwn import * 
from Crypto.Util.number import *
import os
from sage.all import *

conn = remote("blackhat4-4a018cd32538b915dab7182b963d8aed-0.chals.bh.ctf.sa", 443, ssl=True, sni="blackhat4-4a018cd32538b915dab7182b963d8aed-0.chals.bh.ctf.sa")

# conn.interactive()

def getMulN(st):
    conn.recvlines(6)
    conn.sendline(b"E")
    conn.recvline()
    conn.sendline(str(st).encode())
    conn.recvlines(2)
    enc_st = int(conn.recvline().split()[-1])
    conn.recvline()

    conn.recvlines(6)
    conn.sendline(b"D")
    conn.recvline()
    conn.sendline(str(-enc_st).encode())
    conn.recvlines(2)
    dec_st = int(conn.recvline().split()[-1])

    print(dec_st)

    conn.recvlines(5)

    return dec_st + st

conn.recvlines(3)

conn.sendline(b"a")

for i in range(8):
    conn.recvline()

n_hash = conn.recvline().split()[-1]
e = int(conn.recvline().split()[-1])

print("n_hash", n_hash)
print(e)
assert e == 65537

conn.recvline()
conn.recvline()

s = conn.recvline()
flag_enc = int(s.split()[-1])

print("flag_enc", flag_enc)

conn.recvline()

conn.recvlines(3)

conn.recvline()

print("start")

N1 = getMulN(2)
N2 = getMulN(3)

print("N1:", N1)
print("N2:", N2)

N = GCD(N1, N2)

print("N", N)

for i in range(2, 1000):
    while N % i == 0:
        N //= i

print(N)

print(hashlib.sha256(str(N).encode()).hexdigest())