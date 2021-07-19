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


# r = remote('tiramisu.2021.ctfcompetition.com', 1337)

import argparse
import pwnlib
import challenge_pb2
import struct
import sys

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

context.log_level = "error"
warnings.filterwarnings("ignore")

FLAG_CIPHER_KDF_INFO = b"Flag Cipher v1.0"
CHANNEL_CIPHER_KDF_INFO  = b"Channel Cipher v1.0"
CHANNEL_MAC_KDF_INFO = b"Channel MAC v1.0"

IV = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
p224 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
a224 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
b224 = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4

p256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
X256 = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Y256 = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

RES = 0
MOD = 1

class AuthCipher(object):
	def __init__(self, secret, cipher_info, mac_info):
		self.cipher_key = self.derive_key(secret, cipher_info)
		self.mac_key = self.derive_key(secret, mac_info)

	def derive_key(self, secret, info):
		hkdf = HKDF(
			algorithm=hashes.SHA256(),
			length=16,
			salt=None,
			info=info,
		)
		return hkdf.derive(secret)

	def encrypt(self, iv, plaintext):
		cipher = Cipher(algorithms.AES(self.cipher_key), modes.CTR(iv))
		encryptor = cipher.encryptor()
		ct = encryptor.update(plaintext) + encryptor.finalize()

		h = hmac.HMAC(self.mac_key, hashes.SHA256())
		h.update(iv)
		h.update(ct)
		mac = h.finalize()

		out = challenge_pb2.Ciphertext()
		out.iv = iv
		out.data = ct
		out.mac = mac
		return out

def handle_pow(tube):
	raise NotImplemented()

def read_message(tube, typ):
	n = struct.unpack('<L', tube.recvnb(4))[0]
	buf = tube.recvnb(n)
	msg = typ()
	msg.ParseFromString(buf)
	return msg

def write_message(tube, msg):
	buf = msg.SerializeToString()
	tube.send(struct.pack('<L', len(buf)))
	tube.send(buf)

def name2proto(name):
	if name == 'secp224r1':
		return challenge_pb2.EcdhKey.CurveID.SECP224R1
	if name == 'secp256r1':
		return challenge_pb2.EcdhKey.CurveID.SECP256R1

def curve2proto(c):
	return name2proto(c.name)

def key2proto(key):
	assert(isinstance(key, ec.EllipticCurvePublicKey))
	out = challenge_pb2.EcdhKey()
	out.curve = curve2proto(key.curve)
	x, y = key.public_numbers().x, key.public_numbers().y
	out.public.x = x.to_bytes((x.bit_length() + 7) // 8, 'big')
	out.public.y = y.to_bytes((y.bit_length() + 7) // 8, 'big')
	return out

def num2proto(x, y, curvename):
	out = challenge_pb2.EcdhKey()
	out.curve = name2proto(curvename)
	out.public.x = x.to_bytes((x.bit_length() + 7) // 8, 'big')
	out.public.y = y.to_bytes((y.bit_length() + 7) // 8, 'big')
	return out

def proto2key(key):
	assert(isinstance(key, challenge_pb2.EcdhKey))
	assert(key.curve == challenge_pb2.EcdhKey.CurveID.SECP224R1)
	curve = ec.SECP224R1()
	x = int.from_bytes(key.public.x, 'big')
	y = int.from_bytes(key.public.y, 'big')
	public = ec.EllipticCurvePublicNumbers(x, y, curve)
	return ec.EllipticCurvePublicKey.from_encoded_point(curve, public.encode_point())


LST = []

def run_session_brute(args):
	myx, myy, shared, val = args
	tube = pwnlib.tubes.remote.remote('tiramisu.2021.ctfcompetition.com', 1337)
	tube.recvuntil('== proof-of-work: ')
	if tube.recvline().startswith(b'enabled'):
		handle_pow()

	server_hello = read_message(tube, challenge_pb2.ServerHello)
	server_key = proto2key(server_hello.key)
	
	client_hello = challenge_pb2.ClientHello()
	client_hello.key.CopyFrom(num2proto(myx, myy, 'secp256r1'))

	write_message(tube, client_hello)

	shared_key = shared.to_bytes(28, 'big')
	
	channel = AuthCipher(shared_key, CHANNEL_CIPHER_KDF_INFO, CHANNEL_MAC_KDF_INFO)
	msg = challenge_pb2.SessionMessage()
	msg.encrypted_data.CopyFrom(channel.encrypt(IV, b'hello'))
	write_message(tube, msg)

	reply = read_message(tube, challenge_pb2.SessionMessage)
	if len(str(reply)) != 0:
		return val
	
	return None

def solve_key():
	global RES, MOD, LST
	cnt = 0
	while True:
		cnt += 1
		print("cnt:", cnt)
		# myy^2 = myx^3 - 3 myx + b (in secp256r1)
		# myy^2 = myx^3 - 3 myx + ?? (in "secp224r1")
		# that curve must have small order
		
		u = rand.randint(0, 1 << 223)
		v = rand.randint(0, 1 << 223)

		b = (v * v - u * u * u + 3 * u) % p224
		E = EllipticCurve(GF(p224), [-3, b])

		ORD = E.order()

		for i in range(300, 1000):
			if isPrime(i) and MOD % i != 0 and ORD % i == 0:
				GG = None
				while True:
					G = E.random_point()
					GG = (ORD // i) * G
					if GG != GG + GG:
						break
				myx = int(crt(X256, int(GG.xy()[0]), p256, p224))
				myy = int(crt(Y256, int(GG.xy()[1]), p256, p224))
				params = []
				print(i)
				for j in range(1, i // 2 + 1):
					CC = j * GG
					shared = int(CC.xy()[0])
					params.append((myx, myy, shared, j))
				ex = False
				pool = mp.Pool(12)
				for result in pool.imap_unordered(run_session_brute, params):
					if result != None:
						ex = True
						RES = int(crt(RES, result, MOD, i))
						MOD = MOD * i // GCD(MOD, i)
						LST.append((result, i))
						break
				if ex == False:
					RES = int(crt(RES, 0, MOD, i))
					MOD = MOD * i // GCD(MOD, i)
					LST.append((0, i))
				print(MOD)
				print(LST)

				
		print(RES)
		print(MOD)
		print(LST)
		if MOD >= (1 << 224):
			break

MOD = 540673364353189832391160053362578990889676935004508961652820694068949
LST = [(15, 421), (65, 433), (112, 607), (47, 311), (378, 977), (266, 643), (99, 461), (44, 449), (206, 503), (32, 647), (240, 709), (346, 853), (124, 401), (174, 577), (244, 571), (11, 601), (429, 859), (164, 353), (171, 479), (53, 881), (121, 641), (226, 661), (4, 317), (139, 599), (35, 751)]
PROD = 1
CV = []

for i in range(25):
	res, mod = 0, 1
	for j in range(25):
		u, v = LST[j]
		if j != i:
			res = crt(res, 0, mod, v)
		else:
			res = crt(res, 1, mod, v)
		mod = mod * v
	PROD = mod
	CV.append(res)

def run_session():
	tube = pwnlib.tubes.remote.remote('tiramisu.2021.ctfcompetition.com', 1337)
	print(tube.recvuntil('== proof-of-work: '))
	if tube.recvline().startswith(b'enabled'):
		handle_pow()

	server_hello = read_message(tube, challenge_pb2.ServerHello)
	iv = server_hello.encrypted_flag.iv
	data = server_hello.encrypted_flag.data
	xx = int.from_bytes(server_hello.key.public.x, "big")
	yy = int.from_bytes(server_hello.key.public.y, "big")
	return iv, data, xx, yy

def test_keys(args):
	iviv, ctct, LSV, CV, PROD, RANGE = args
	BOUND = (1 << 224)
	for i in range(RANGE[0], RANGE[1]):
		res = 0
		for j in range(25):
			u, v = LSV[j]
			if ((i >> j) & 1) == 0:
				res += CV[j] * u
			else:
				res += CV[j] * (v-u)
		res = res % PROD
		sec = int(res)
		if sec > BOUND:
			continue
		sec = sec.to_bytes(28, "big")
		hkdf = HKDF(
				algorithm=hashes.SHA256(),
				length=16,
				salt=None,
				info=FLAG_CIPHER_KDF_INFO,
			)
		key = hkdf.derive(sec)
		cipher = Cipher(algorithms.AES(key), modes.CTR(iviv))
		decryptor = cipher.encryptor()
		flag = decryptor.update(ctct) + decryptor.finalize()
		if b"ctf{" in flag or b"CTF{" in flag:
			print(flag)
			return flag
	return None

iv, ct, xx, yy = run_session()

NUM = 12
pool = mp.Pool(12)
batch = 50000
nonce = 0

while True:
	nonce_range = [(nonce + i * batch, nonce + i * batch + batch) for i in range(NUM)]
	params = [(iv, ct, LST, CV, PROD, RANGE) for RANGE in nonce_range]
	solutions = pool.map(test_keys, params)
	solutions = list(filter(None, solutions))
	print("Checked", nonce + batch * NUM)
	if len(solutions) != 0:
		print(solutions)
	nonce += batch * NUM
	if nonce > (1 << 25):
		break
