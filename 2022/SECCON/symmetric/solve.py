from sage.all import * 
from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from tqdm import tqdm

'''
key 16 bytes
nonce 16 bytes

encrypt
    data = secret_spell
    ctxt, tag <- GCM(key, nonce)(secret_spell)
    ofb_input = pad(tag + nonce + ctxt, 16)
    ofb_iv <- random 16 bytes
    ret = ofb_iv + OFB(key, iv)(ofb_input)

data
    ofb_iv = data[:16]
    ofb_ciphertext = data[16:]
    
    decrypt attempt + unpad -> if fail, ofb error

    now know tag + nonce + xtxt
    -> decrypt attempt. if fail, gcm error

    plaintext should be "give me key", should know the secret spell thing

    also given decryption oracle
'''

secret_spell = b"S" * 16
key = b"k" * 16
nonce = b"n" * 16


def encrypt():
    data = secret_spell
    gcm_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    gcm_ciphertext, gcm_tag = gcm_cipher.encrypt_and_digest(data)

    ofb_input = pad(gcm_tag + gcm_cipher.nonce + gcm_ciphertext, 16)

    print("internal", gcm_tag + gcm_cipher.nonce + gcm_ciphertext)

    ofb_iv = get_random_bytes(16)
    ofb_cipher = AES.new(key, AES.MODE_OFB, iv=ofb_iv)
    ciphertext = ofb_cipher.encrypt(ofb_input)
    return ofb_iv + ciphertext


def decrypt(data):
    ofb_iv = data[:16]
    ofb_ciphertext = data[16:]
    ofb_cipher = AES.new(key, AES.MODE_OFB, iv=ofb_iv)

    try:
        m = ofb_cipher.decrypt(ofb_ciphertext)
        temp = unpad(m, 16)
    except:
        return b"ofb error"

    try:
        gcm_tag = temp[:16]
        gcm_nonce = temp[16:32]
        gcm_ciphertext = temp[32:]
        gcm_cipher = AES.new(key, AES.MODE_GCM, nonce=gcm_nonce)

        plaintext = gcm_cipher.decrypt_and_verify(gcm_ciphertext, gcm_tag)
    except:
        return b"gcm error"

    if b"give me key" == plaintext:
        your_spell = input("ok, please say secret spell:").encode()
        if your_spell == secret_spell:
            return b"solved!!!! let's go"
        else:
            return b"Try Harder"

    return b"ok"

POL = PolynomialRing(GF(2), 'a')
a = POL.gen()
F = GF(2 ** 128, name = 'a', modulus = a ** 128 + a ** 7 + a ** 2 + a + 1)

def aes_enc(p, k):
    cipher = AES.new(key = k, mode = AES.MODE_ECB)
    return cipher.encrypt(p)

def int_to_finite(v): # int -> finite 
    bin_block = bin(v)[2:].zfill(128)
    res = 0
    for i in range(128):
        res += (a ** i) * int(bin_block[i])
    return F(res)

def bytes_to_finite(v): # bytes -> long -> finite
    v = bytes_to_long(v)
    return int_to_finite(v)

def finite_to_int(v): # finite field -> int repr
    v = POL(v)
    res = v.coefficients(sparse = False)
    ret = 0
    for i in range(len(res)):
        ret += int(res[i]) * (1 << (127 - i))
    return ret

def finite_to_bytes(v): # finite -> int -> bytes
    cc = finite_to_int(v)
    return long_to_bytes(cc, blocksize = 16)

def hasher(H, v): # H, v -> GHASH
    H_f = bytes_to_finite(H)
    ret = F(0)
    res = bytes_to_long(v)
    bin_block = bin(res)[2:].zfill(256)
    bas = []
    for i in range(256):
        cc = F(a ** int(i % 128)) * F(H_f ** (2 - i // 128)) 
        bas.append(finite_to_int(cc))
        ret += F(a ** int(i % 128)) * F(H_f ** (2 - i // 128)) * int(bin_block[i])
    return bas, finite_to_int(ret)

def byteXor(a, b):
    return bytes(u ^ v for (u, v) in zip(a, b))


def getAESEnc(ptxt):
    ofb_iv = ptxt
    dec = [0] * 16
    for i in tqdm(range(15, -1, -1)):
        ctxt = [0] * 16
        len_pad = 16 - i
        for j in range(i + 1, 16):
            ctxt[j] = dec[j] ^ len_pad
        for j in range(256):
            ctxt[i] = j
            oracle = decrypt(ofb_iv + bytes(ctxt))
            if oracle != b"ofb error":
                dec[i] = j ^ len_pad
    return bytes(dec)

final_ctxt = bytes.fromhex(encrypt().hex())

enc_zero = getAESEnc(b"\x00" * 16)

ofb_iv = final_ctxt[:16]

iv1 = getAESEnc(ofb_iv)
iv2 = getAESEnc(iv1)
iv3 = getAESEnc(iv2)
iv4 = getAESEnc(iv3)

gcm_tag = byteXor(final_ctxt[16:32], iv1)
gcm_nonce = byteXor(final_ctxt[32:48], iv2)
gcm_ciphertext = byteXor(final_ctxt[48:64], iv3)
pads = byteXor(final_ctxt[64:80], iv4)

print("internal get", gcm_tag + gcm_nonce + gcm_ciphertext + pads)


H = enc_zero 
y_0 = long_to_bytes(hasher(H, gcm_nonce + b"\x00" * 8 + long_to_bytes(128, 8))[1], 16)
y_1 = long_to_bytes(bytes_to_long(y_0) + 1)

secret_spell = byteXor(getAESEnc(y_1), gcm_ciphertext)

print("spell", secret_spell)

ptxt_target = b"give me key" # len 11
ctxt_target = byteXor(getAESEnc(y_1)[:11], ptxt_target)

tag_1 = long_to_bytes(hasher(H, ctxt_target + b"\x00" * 5 + b"\x00" * 8 + long_to_bytes(88, 8))[1], 16)
tag_2 = aes_enc(y_0, key)

tag_target = byteXor(tag_1, tag_2)

goal = pad(tag_target + gcm_nonce + ctxt_target, 16)

final_flag_ctxt = ofb_iv + byteXor(goal[:16], iv1) + byteXor(goal[16:32], iv2) + byteXor(goal[32:48], iv3) + byteXor(goal[48:64], iv4)

print(decrypt(final_flag_ctxt))
