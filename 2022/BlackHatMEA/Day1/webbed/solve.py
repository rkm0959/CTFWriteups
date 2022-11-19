from pwn import * 
from Crypto.Util.number import *
import os
from sage.all import *
import requests 
import json
import random as rand
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Global parameters
ALLOWED = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'

print(len(ALLOWED) / 256)

# Classes
class Crypto:
	def __init__(self, key):
		self.key = key

	def encrypt(self, msg):
		pdm = pad(msg, 16)
		riv = os.urandom(16)
		aes = AES.new(self.key, AES.MODE_CBC, riv)
		cip = riv + aes.encrypt(pdm)
		return cip

	def decrypt(self, cip):
		riv, cip = cip[:16], cip[16:]
		aes = AES.new(self.key, AES.MODE_CBC, riv)
		pdm = aes.decrypt(cip)
		msg = unpad(pdm, 16)
		return msg

	def remove_illegal_chars(self, token):
		il = token.index(b': "') + 3
		ir = il + token[il:].index(b'"')
		return token[:il] + bytes(i for i in token[il:ir] if i in ALLOWED) + token[ir:]

	def gen_token(self, username, admin=False):
		raw = {
				'username' : username, 
				'admin'	   : admin
			  }
		tok = json.dumps(raw).encode()
		enc = self.encrypt(tok)
		return tok, enc.hex()

	def validate_token(self, enc):
		try:
			tok = self.remove_illegal_chars(self.decrypt(enc))
			raw = json.loads(tok)
			return raw['username'], raw['admin']
		except:
			raise ValueError()

def byteXor(a, b):
    assert len(a) == 16 and len(b) == 16
    return bytes(u ^ v for (u, v) in zip(a, b))

import string 
from tqdm import tqdm

hit = 0

key = os.urandom(32)
crypto = Crypto(key)

for it in tqdm(range(1000000)):
    rd = "".join((rand.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(15)))
    tt, enc = crypto.gen_token(rd)

    padded = pad(tt, 16)
    enc = bytes.fromhex(enc)

    IV = enc[:16]
    C1 = enc[16:32]
    C2 = enc[32:48]
    C3 = enc[48:64]

    new_cc = IV + C1 + byteXor(C2, byteXor(b'"admin": false}\x01', b',"admin": true}\x01')) + C3

    tok = crypto.remove_illegal_chars(crypto.decrypt(new_cc))

    try:
        raw = json.loads(tok)
        assert raw["username"] == rd[:2]
        assert raw["admin"] == True
        hit += 1
    except:
        pass

print(hit)