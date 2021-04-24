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

flag =  0x12f47f77c4b5a72a0d14a066fedc80ba6064058c900a798f1658de60f13e1d8f21106654c4aac740fd5e2d7cf62f0d3284c2686d2aac261e35576df989185fee449c20efa171ff3d168a04bce84e51af255383a59ed42583e93481cbfb24fddda16e0a767bff622a4753e1a5df248af14c9ad50f842be47ebb930604becfd4af04d21c0b2248a16cdee16a04b4a12ac7e2161cb63e2d86999a1a8ed2a8faeb4f4986c2a3fbd5916effb1d9f3f04e330fdd8179ea6952b14f758d385c4bc9c5ae30f516c17b23c7c6b9dbe40e16e90d8734baeb69fed12149174b22add6b96750e4416ca7addf70bcec9210b967991e487a4542899dde3abf3a91bbbaeffae67831c46c2238e6e5f4d8004543247fae7ff25bbb01a1ab3196d8a9cfd693096aabec46c2095f2a82a408f688bbedddc407b328d4ea5394348285f48afeaafacc333cff3822e791b9940121b73f4e31c93c6b72ba3ede7bba87419b154dc6099ec95f56ed74fb5c55d9d8b3b8c0fc7de99f344beb118ac3d4333eb692710eaa7fd22

def kthp(n, k):
	if n == 0:
		return 0
	lef = 1
	rig = 2
	best = 0
	while rig ** k < n:
		rig = rig << 1
	while lef <= rig:
		mid = (lef + rig) // 2
		if mid ** k <= n:
			best = mid
			lef = mid + 1
		else:
			rig = mid - 1
	return best

w = 25965460884749769384351428855708318685345170011800821829011862918688758545847199832834284337871947234627057905530743956554688825819477516944610078633662855

def get_q_from_p(p):
    x = p + 1328
    y = p + 1329
    z = w * x * y // (w * x + w * y - 4 * x * y)
    return z + 1

# p^3q is around 3000 bits
# w is around 500 bits
# note that 2/p >~ 4/w so p < 500bits
# so p ~ 500 bits, q ~ 1500 bits
# solve q in terms of p -> it gives q = (some poly of p) / (some poly of p)
# the numerator can be bounded to ~ 1500 bits
# therefore, the denominator must be small : brute force here

# this is the denominator
A = 4
B = - 51930921769499538768702857711416637370690340023601643658023725837377517091694399665668568675743894469254115811061487913109377651638955033889220157267315082
C = - 68990229570780137254221746469617002746962116721354783599684519774956031456316009955840693485725763802404092854995186692565808210202351762521828978929635146087

for i in tqdm(range(-1 << 15, 1 << 15)):
    # Ax^2 + Bx + C = i
    p = (-B + kthp(B * B - 4 * A * (C - i), 2)) // (2 * A)
    if isPrime(p):
        q = get_q_from_p(p)
        if isPrime(q):
            N = p * p * p * q
            phi = p * p * (p-1) * (q-1)
            e = 0x10001
            d = inverse(e, phi)
            print(long_to_bytes(pow(flag, d, N))) 
