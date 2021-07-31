from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa

'''
(x, y) + (x, y)

= 2x * (1 + y^2) / (1 + x^2) / (1 - y^2)
= 2y * (1 + x^2) / (1 + y^2) / (1 - x^2)
'''

k = '''
000bfdc32162934ad6a054b4b3db8578674e27a165113f8ed018cbe9112
4fbd63144ab6923d107eee2bc0712fcbdb50d96fdf04dd1ba1b69cb1efe
71af7ca08ddc7cc2d3dfb9080ae56861d952e8d5ec0ba0d3dfdf2d12764
'''.replace('\n', '')

# (x+1)(y-1) sq

def inthroot(a, n):
    return a.nth_root(n, truncate_mode=True)[0]

target = 4 * int(k, 16)

target = inthroot(Integer(target), 2)
target = int(target)

# (x+1)(y-1) = target

print(target)

l = divisors(target)

for x in l:
    y = target // x
    flag = long_to_bytes(x - 1) + long_to_bytes(y + 1)
    if b"CCTF" in flag:
        print(flag)

'''
x1, y1 = (43221592968083984976181631439136832753226493145720904794627744437913710322427, 93066627696812415949933746386887761934091878058969329232913770674862462325151)
x2, y2 = (1676397438287474195941607302240268499358607402858286086942132941383711301685, 68799238806663834908952910526822575025741016194138227414208649405169781499078)

# a / b = (x1 * x1 - 1) * y1 / (y1 * y1 - 1) / x1
# a / b = (x2 * x2 - 1) * y2 / (y2 * y2 - 1) / x2 

res1 = (x1 * x1 - 1) * y1 * x2 * (y2 * y2 - 1)
res2 = (x2 * x2 - 1) * y2 * x1 * (y1 * y1 - 1)

diff = abs(res1 - res2)

print(diff)
'''

