from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
from os import urandom
import multiprocessing as mp

r = remote('139.59.190.72', '30463')
p = 2**1024 + 1657867
g = 3
order = 89884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056939935696678829394884407208311246423715319737062188883946712432742638151109800623047059726541476042502884419075341171231440736956555270413618581675255342293149119973622969239858152417678164812112897541

message = bytes_to_long(b'get_flag') * (2 ** 1040) + order
rr = order 
ss = order 


r.recvline()
r.recvline()
r.sendline(hex(message)[2:])
r.sendline(str(rr))
r.sendline(str(ss))

for i in range(100):
    print(r.recvline())