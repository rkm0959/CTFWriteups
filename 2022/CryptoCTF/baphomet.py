from sage.all import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, inverse, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import * 
import random as rand
from tqdm import tqdm
import requests
import json
from base64 import b64encode

f = open('flag.enc', 'rb')
enc = f.read()

print(enc)
print(len(enc))

def encrypt(msg):
    ba = b64encode(msg.encode('utf-8'))
    print(len(ba), ba)
    print(ba.decode("utf-8"))
    baph, key = '', ''

    for b in ba.decode('utf-8'):
        if b.islower():
            baph += b.upper()
            key += '0'
        else:
            baph += b.lower()
            key += '1'

    baph = baph.encode('utf-8')
    key = int(key, 2).to_bytes(len(key) // 8, 'big')

    enc = b''
    for i in range(len(baph)):
        enc += (baph[i] ^ key[i % len(key)]).to_bytes(1, 'big')

    return enc

st = b"Q0NURnt"

baph = ""

for b in st.decode('utf-8'):
    if b.islower():
        baph += b.upper()
    else:
        baph += b.lower()

baph = baph.encode("utf-8")
keys = b""

for i in range(len(baph)):
    keys += (baph[i] ^ enc[i]).to_bytes(1, 'big')

print(keys)

keys = keys[:6]

actual_baph = b""

for i in range(len(enc)):
    actual_baph += bytes([keys[i % 6] ^ enc[i]])

actual_baph = actual_baph.decode("utf-8")

flag = ""
for b in actual_baph:
    if b.islower():
        flag += b.upper()
    else:
        flag += b.lower()

print(base64.b64decode(flag))