# RC4 Writeup

We note that RC4 is ultimately a stream cipher, so $C = P \oplus K$ with $K$ depending on our key. 

Therefore, if we have a plaintext/ciphertext pair $C_1, P_1$, we can recover $K = C_1 \oplus P_1$. 

Now we can decrypt any ciphertext $C_2$ as $P_2 = C_2 \oplus K = C_2 \oplus C_1 \oplus P_1$. This solves the problem. 

```py
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa

def bytexor(a, b):
	assert len(a) == len(b)
	return bytes(x ^ y for x, y in zip(a, b))

msg = b"RC4 is a Stream Cipher, which is very simple and fast."

res1 = '634c3323bd82581d9e5bbfaaeb17212eebfc975b29e3f4452eefc08c09063308a35257f1831d9eb80a583b8e28c6e4d2028df5d53df8'
res2 = '624c5345afb3494cdd6394bbbf06043ddacad35d28ceed112bb4c8823e45332beb4160dca862d8a80a45649f7a96e9cb'

res1 = binascii.unhexlify(res1)
res2 = binascii.unhexlify(res2)

msg = msg[:48]
res1 = res1[:48]

flag = bytexor(msg, res1)
flag = bytexor(flag, res2)

print(flag)
```

flag : ``SCTF{B10ck_c1pH3r_4nd_5tr3am_ciPheR_R_5ymm3tr1c}``