from sage.all import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# from pwn import * 
from struct import *

import random as rand

key = "4dcceb8802ae3c45fe80ccb364c8de19f2d39aa8ebbfb0621623e67aba8ed5bc"
enc = "e67a67efee3a80b66af0c33260f96b38e4142cd5d9426f6f156839f2e2a8efe8"


# key = passphrase ^ flag

# passphrase ^ encrypt(key) ^ rand

def aniely_stream(passphrase):
	def mixer(u, v):
		return ((u << v) & 0xffffffff) | u >> (32 - v)

	def forge(w, a, b, c, d):
		for i in range(2):
			w[a] = (w[a] + w[b]) & 0xffffffff
			w[d] = mixer(w[a] ^ w[d], 16 // (i + 1))
			w[c] = (w[c] + w[d]) & 0xffffffff
			w[b] = mixer(w[b] ^ w[c], (12 + 2*i) // (i + 1))

	bring = [0] * 16
	bring[:4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
	bring[4:12] = unpack('<8L', passphrase)
	bring[12] = bring[13] = 0x0
	bring[14:] = [0] * 2

	while True:
		w = list(bring)
		for _ in range(10):
			forge(w, 0x0, 0x4, 0x8, 0xc)
			forge(w, 0x1, 0x5, 0x9, 0xd)
			forge(w, 0x2, 0x6, 0xa, 0xe)
			forge(w, 0x3, 0x7, 0xb, 0xf)
			forge(w, 0x0, 0x5, 0xa, 0xf)
			forge(w, 0x1, 0x6, 0xb, 0xc)
			forge(w, 0x2, 0x7, 0x8, 0xd)
			forge(w, 0x3, 0x4, 0x9, 0xe)
		for c in pack('<16L', *((w[_] + bring[_]) & 0xffffffff for _ in range(16))):
			yield c
		bring[12] = (bring[12] + 1) & 0xffffffff
		if bring[12] == 0:
			bring[13] = (bring[13] + 1) & 0xffffffff

def aniely_encrypt(msg, passphrase):
	if len(passphrase) < 32:
		passphrase = (passphrase * (32 // len(passphrase) + 1))[:32]
	rand = b"\x00\x00" * 16
	return bytes(a ^ b ^ c for a, b, c in zip(msg, aniely_stream(passphrase), rand))

key = "4dcceb8802ae3c45fe80ccb364c8de19f2d39aa8ebbfb0621623e67aba8ed5bc"
enc = "e67a67efee3a80b66af0c33260f96b38e4142cd5d9426f6f156839f2e2a8efe8"

# enc = passphrase ^ random ^ stream(key)
# key = passphrase ^ flag
# flag = key ^ passphrase = key ^ enc ^ random ^ stream(key)

key = bytes.fromhex(key)
enc = bytes.fromhex(enc)

print(len(key))
print(len(enc))

cc = bytes(a ^ b ^ c for a, b, c in zip(key, enc, aniely_stream(key)))

change0 = cc[0] ^ ord('C')
change1 = cc[1] ^ ord('C')

flag = b""

for i in range(len(cc)):
    if i % 2 == 0:
        t = cc[i] ^ change0
        flag += bytes([t])
    if i % 2 == 1:
        t = cc[i] ^ change1 
        flag += bytes([t])

print(flag)