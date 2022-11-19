
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os, time
import requests
from tqdm import tqdm
class json:
    def loads(packet):
        jstr = packet[packet.index(123)+1:packet.index(125)].split(b',')
        jlst = [[j.strip(b' "').decode() for j in i.split(b':')] for i in jstr]
        jobj = {}
        for key, value in jlst:
            if key in jobj:
                raise ValueError()
            else:
                jobj[key] = value
        return jobj

    def dumps(packet):
        jstr = '{'
        for key in packet.keys():
            value = packet[key]
            if type(value) in [int,dict,list,float]:
                jstr += '"{}": {}, '.format(key, value)
            else:
                jstr += '"{}": "{}", '.format(key, value)
        jstr = jstr[:-2]
        jstr += '}'
        return jstr

url = "https://blackhat4-a2c654e611fd4ff0f2fd14d3e376dbb9-0.chals.bh.ctf.sa"

def getToken(username):
    req = requests.get(url + "/register/" + username + "/",  allow_redirects=False)
    token = req.headers["Set-Cookie"].split(";")
    for x in token:
        if "access_token=" in x:
            return bytes.fromhex(x[13:])


def success_acc(query_token, print_them):
    cookies = {"access_token": query_token.hex()}
    req = requests.get(url, allow_redirects=True, cookies = cookies)
    if print_them:
        print(req.content)
    if b"ERROR" in req.content:
        return False
    return True

def byteXor(a, b):
    assert len(a) == 16 and len(b) == 16
    return bytes(u ^ v for (u, v) in zip(a, b))

enc_token = getToken("w" * 15)

def decryption_oracle(block):
    assert len(block) == 16
    enc_base = enc_token[:144]
    found_dec = [0] * 16
    for i in tqdm(range(15, -1, -1)):
        C9 = [0] * 16
        pad_length = 16 - i
        for j in range(i + 1, 16):
            C9[j] = pad_length ^ found_dec[j]
        for j in tqdm(range(256)):
            C9[i] = j
            query_token = enc_base + bytes(C9) + block
            if success_acc(query_token, False):
                found_dec[i] = pad_length ^ j
                break
    
    return bytes(found_dec)

'''
res = b""
for i in range(len(enc_token) // 16 - 1):
    U = enc_token[16 * i : 16 * i + 16]
    V = enc_token[16 * i + 16 : 16 * i + 32]
    tt = byteXor(decryption_oracle(V), U)
    print(tt)
    res += tt
'''

target = {
    "user": "admin",
    "iat": 100,
    "priv": "REMOTE__Vault.access",
    "code": 2986943086169684198385382795034351559084980019081375837383
}

cc = pad(json.dumps(target).encode(), 16)

enc_final = [b""] * (len(cc) // 16 + 1)
enc_final[-1] = b"\x00" * 16

for i in tqdm(range(len(enc_final) - 1, 0, -1)):
    # D_K(enc_final[i]) ^ enc_final[i - 1] = cc[i - 1]
    enc_final[i - 1] = byteXor(decryption_oracle(enc_final[i]), cc[16 * (i - 1): 16 * i])
    print(enc_final[i - 1])



grand_final = b""
for i in range(len(enc_final)):
    grand_final += enc_final[i]

success_acc(grand_final, True)
