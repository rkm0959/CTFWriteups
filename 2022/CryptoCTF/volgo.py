from sage.all import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, inverse, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import * 
import random as rand
from tqdm import tqdm
import requests
import json

def get_ciphertext(s):
    url = "http://03.cr.yp.toc.tf:11117/m209/encipher"
    data = { "plain": s }
    res = requests.post(url, data)
    return json.loads(res.text)["cipher"]

st = "IISNJ IFFAA TYPMO WDJHA ZMNBD LKUAY TYPVD UGAYU OQMOO YRVUS SLFZI IXKVW LYUGT JWTYV XNEYU HLQVV IXUMJ BKNUQ WMLQT QKIWV UXOCA CVSPG UKJQG XCSFI RJEKU BWLBM AVRFW DMOPT VFXTD VROND XSEHF ZLWEJ VOVSX IISNJ IFFAA"

en = "A" * 155
en = get_ciphertext(en)

print(len(st))
print(len(en))
res = b""
for i in range(len(st)):
    if st[i] == en[i] and st[i] == " ":
        continue
    cc = bytes([(ord(en[i]) - ord(st[i])) % 26 + ord('A')])
    if b"Z" == cc:
        res += b" "
    else:
        res += cc
print(res)    