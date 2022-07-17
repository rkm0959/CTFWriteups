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

conn = remote("02.cr.yp.toc.tf", 13771)

perm = [[] for _ in range(45)]

perm[3] = [2, 3, 1]
perm[5] = [2, 3, 5, 4, 1]

for i in range(6, 45):
    if i % 3 == 1:
        continue
    perm[i] = [2, 3]
    for j in range(2, i - 1):
        perm[i].append(perm[i-3][j-2] + 3)
    perm[i].append(1)
    assert len(perm[i]) == i

for i in range(8):
    conn.recvline()

for i in range(3, 41):
    print(conn.recvline())
    if i % 3 == 1:
        conn.sendline(b"TINP")
        print(conn.recvline())
        continue
    else:
        st = ""
        for x in perm[i]:
            st += str(x) + ", "
        st = st[:-2]
        conn.sendline(st.encode())
        print(conn.recvline())

print(conn.recvline())
