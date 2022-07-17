from sage.all import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, inverse, getPrime
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from pwn import * 
import random as rand
from tqdm import tqdm
import requests
import json
from hashlib import sha256
from base64 import b64encode
import time 

SBOX = [
		0xbe, 0xc5, 0x0f, 0x83, 0xb2, 0x77, 0xa8, 0x40, 0x4c, 0x53, 0x65, 0xd6, 0x27, 0xa7, 0x7c, 0x48, 
		0x1a, 0x60, 0x30, 0x17, 0xf3, 0x80, 0x04, 0x74, 0xd2, 0x5a, 0x2c, 0x8e, 0xa0, 0x32, 0x38, 0xcb, 
		0xe5, 0x4d, 0x19, 0x8f, 0xd9, 0x6d, 0x86, 0x58, 0xfc, 0xfa, 0xba, 0xdd, 0xc7, 0x57, 0xc1, 0x1c, 
		0x6a, 0x0c, 0x7b, 0x4b, 0xc8, 0x52, 0x54, 0x82, 0x47, 0x5d, 0xc9, 0xe8, 0x6b, 0xdb, 0x5e, 0x08,
		0xfb, 0x8d, 0x0e, 0x43, 0x37, 0x39, 0x50, 0x91, 0x7e, 0xf4, 0xe7, 0x35, 0xb8, 0x88, 0x20, 0x8b, 
		0x90, 0xe9, 0xee, 0xd5, 0xd3, 0xc3, 0xff, 0xa9, 0xae, 0x64, 0xf5, 0xac, 0x11, 0x4a, 0x76, 0x06, 
		0x18, 0x8a, 0xa3, 0xec, 0x56, 0x94, 0xdf, 0x42, 0x00, 0x22, 0xda, 0x6c, 0xb1, 0x12, 0xf2, 0xfe, 
		0xbf, 0x21, 0x1b, 0x4e, 0x9f, 0x97, 0xa6, 0x2b, 0x0b, 0xd4, 0x93, 0xc6, 0x03, 0x71, 0x14, 0x7a, 
		0x02, 0x0a, 0xc4, 0xdc, 0x36, 0x96, 0xd0, 0x09, 0x33, 0x26, 0xbc, 0x1d, 0xb6, 0xde, 0xe6, 0xe3, 
		0xeb, 0x28, 0x8c, 0x24, 0x99, 0x3f, 0xc0, 0x6f, 0xa2, 0xc2, 0xfd, 0x3c, 0x2d, 0x15, 0xf6, 0xad, 
		0x2f, 0xbd, 0x67, 0x05, 0x68, 0xa1, 0x69, 0x13, 0xca, 0x9d, 0x3a, 0x01, 0x63, 0xd7, 0x75, 0x07, 
		0x59, 0xb9, 0x46, 0xf8, 0xcd, 0x5c, 0x70, 0x95, 0xf9, 0x16, 0x45, 0xd1, 0x98, 0x79, 0x9c, 0x81, 
		0x44, 0x62, 0x6e, 0xb4, 0x34, 0xce, 0x84, 0xab, 0x29, 0x1e, 0x2a, 0x9b, 0xe2, 0x25, 0xb5, 0x87, 
		0x23, 0x3d, 0x5f, 0xaa, 0xf7, 0x9e, 0xed, 0xb3, 0xe1, 0x72, 0x7d, 0x3b, 0xb7, 0x0d, 0x51, 0x9a, 
		0x4f, 0x55, 0xf1, 0xf0, 0xe0, 0x31, 0x7f, 0xbb, 0x89, 0x5b, 0xe4, 0x78, 0x73, 0xef, 0xea, 0x92, 
		0x61, 0x41, 0x1f, 0xcc, 0xb0, 0x49, 0x85, 0x3e, 0x66, 0xaf, 0xd8, 0x2e, 0xa5, 0x10, 0xa4, 0xcf
]

un_sbox = [0] * 256 
for i in range(256):
    un_sbox[SBOX[i]] = i 

def shaim(msg):
    nbit, hmsg = 64, msg.hex()
    hmsg += 'f' + hex(len(msg.hex())*4)[2:]
    hmsg += (nbit - (4*len(hmsg) % nbit)) // 4 * 'f'
    print(hmsg)
    H, SBOX_M  = [], ''
    for i in range (0, len(hmsg) - 1, 2):
        tmp = hex(SBOX[int(hmsg[i:i+2], 16)])[2:]
        tmp = '0' + tmp if len(tmp) % 2 else tmp
        SBOX_M += tmp
    hmsg = SBOX_M
    print(hmsg)
    l = nbit // 4     
    H.append((int(hmsg[0:l], 16)))
    for i in range(1, len(hmsg) // l):
        plain = long_to_bytes(int(hmsg[i*l:(i+1)*l], 16))
        key = long_to_bytes(H[i-1], 8)
        _DES = DES.new(key = key, mode = DES.MODE_OFB, IV = key)
        H.append(bytes_to_long(_DES.encrypt(plain)) ^ bytes_to_long(key))
    dgst = sha256(long_to_bytes(H[-1])).hexdigest()
    return hmsg, H, dgst

def randstr(l):
	rstr = [(string.printable[:62] + '_')[rand.randint(0, 62)] for _ in range(l)]
	return ''.join(rstr).encode('utf-8')

def startFromHmsg(hmsg):
    nbit = 64
    l = nbit // 4     
    H = []
    H.append((int(hmsg[0:l], 16)))
    for i in range(1, len(hmsg) // l):
        plain = long_to_bytes(int(hmsg[i*l:(i+1)*l], 16))
        key = long_to_bytes(H[i-1], 8)
        _DES = DES.new(key = key, mode = DES.MODE_OFB, IV = key)
        H.append(bytes_to_long(_DES.encrypt(plain)) ^ bytes_to_long(key))
    dgst = sha256(long_to_bytes(H[-1])).hexdigest()
    return H, dgst

def startFromPad(hmsg):
    H, SBOX_M  = [], ''
    nbit = 64
    for i in range (0, len(hmsg) - 1, 2):
        tmp = hex(SBOX[int(hmsg[i:i+2], 16)])[2:]
        tmp = '0' + tmp if len(tmp) % 2 else tmp
        SBOX_M += tmp
    hmsg = SBOX_M  
    l = nbit // 4     
    H.append((int(hmsg[0:l], 16)))
    for i in range(1, len(hmsg) // l):
        plain = long_to_bytes(int(hmsg[i*l:(i+1)*l], 16))
        key = long_to_bytes(H[i-1], 8)
        _DES = DES.new(key = key, mode = DES.MODE_OFB, IV = key)
        H.append(bytes_to_long(_DES.encrypt(plain)) ^ bytes_to_long(key))
    dgst = sha256(long_to_bytes(H[-1])).hexdigest()
    return dgst

def is_ascii(s):
    for b in s:
        if b < 32 or b >= 128:
            return False 
    return True
    
def forwarder(s):
    ret = ""
    for i in range(0, len(s) - 1, 2):
        tmp = hex(SBOX[int(s[i:i+2], 16)])[2:]
        tmp = '0' + tmp if len(tmp) % 2 else tmp 
        ret += tmp 
    return ret 

def ascii_transformed(s):
    t = bytes.fromhex(backwarder(s))
    return is_ascii(t)

def backwarder(s):
    ret = ""
    for i in range(0, len(s) - 1, 2):
        tmp = hex(un_sbox[int(s[i:i+2], 16)])[2:]
        tmp = '0' + tmp if len(tmp) % 2 else tmp 
        ret += tmp 
    return ret 


while True:
    conn = remote("01.cr.yp.toc.tf", 37113)
    for i in range(4):
        conn.recvline()
    
    for i in range(4):
        conn.recvline()
    conn.sendline(b"g")

    s = conn.recvline()
    msg = s.split()[-1].decode()[2:-1]

    print(len(msg))
    if len(msg) != 53:
        conn.close()
        time.sleep(1)
        continue
    
    conn.recvline()
    
    msg = msg.encode()
    hmsg, H, dgst = shaim(msg)

    padder = 'f' + hex(4 * 106)[2:] + 'ff'
    SBOX_padder = forwarder(padder)

    print("msg", msg)
    print("target dgst", dgst)

    SBOX_ASCII = set()
    for i in range(32, 128):
        SBOX_ASCII.add(SBOX[i])

    HH = [0 for _ in range(len(H))]
    HH[-1] = H[-1]
    hhmsg = [0 for _ in range(len(H))]


    HH[-2] = H[-2]
    key = long_to_bytes(HH[-2], 8)
    _DES = DES.new(key = key, mode = DES.MODE_OFB, IV = key)
    target = long_to_bytes(HH[-1] ^ HH[-2], 8)
    hhmsg[-1] = _DES.decrypt(target).hex()
    cc = bytes.fromhex(hhmsg[-1])

    for i in range(len(H) - 2, 0, -1):
        for _ in tqdm(range(1 << 24)):
            if i != 1:
                HH[i - 1] = rand.randint(1, (1 << 64) - 1)
            if i == 1:
                hhmsg[0] = forwarder(randstr(8).hex())
                HH[0] = int(hhmsg[0], 16)
            key = long_to_bytes(HH[i - 1], 8)
            _DES = DES.new(key = key, mode = DES.MODE_OFB, IV = key)
            target = long_to_bytes(HH[i] ^ HH[i-1], 8)
            hhmsg[i] = _DES.decrypt(target).hex()
            if ascii_transformed(hhmsg[i]) == False:
                continue
            break
    res = ""
    for i in range(len(H)):
        res += hhmsg[i]
    hmsg_start = backwarder(res)
    des = len(hmsg_start) - 6
    padder = 'f' + hex(des * 4)[2:] + 'ff'
    assert len(padder) == 6 
    true_start = hmsg_start[:-6]
    msgp = bytes.fromhex(true_start)

    for i in range(4):
        conn.recvline()
    
    conn.sendline(b"s")
    conn.recvline()
    conn.sendline(msgp)
    _, _, fin = shaim(msgp)

    print("result dgst", fin)
    print(conn.recvline())
    break