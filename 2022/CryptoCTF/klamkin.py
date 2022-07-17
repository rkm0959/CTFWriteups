from sage.all import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, inverse, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import * 
import random as rand
from tqdm import tqdm
import requests

conn = remote("04.cr.yp.toc.tf", 13777)

for i in range(6):
    print(conn.recvline())


for i in range(4):
    print(conn.recvline())
conn.sendline("G")
q = int(conn.recvline().split()[-1])
r = int(conn.recvline().split()[-1])
s = int(conn.recvline().split()[-1])
    


for i in range(4):
    print(conn.recvline())
conn.sendline("S")

while True:
    c = conn.recvline()

    whi = c.split()[10]
    dg = int(c.split()[12].split(b"-")[0])


    if whi == b"x":
        u = (s * inverse(r, q)) % q 
        u = (u * (1 << (dg - 1))) % q 
        conn.sendline(str(1 << (dg - 1)).encode() + b", " + str(u).encode())
    else:
        u = (r * inverse(s, q)) % q
        u = (u * (1 << (dg - 1))) % q 
        conn.sendline(str(u).encode() + b", " + str(1 << (dg - 1)).encode())

    print(conn.recvline())

