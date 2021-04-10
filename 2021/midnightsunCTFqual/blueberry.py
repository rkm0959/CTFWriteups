from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
# from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random
import multiprocessing as mp
from Crypto.Util import Counter

def trial(s):
    HEADER_FMT = '>5sB8s40si'
    FILE_MAGIC = b'EFC82'
    DATA_MAGIC = b'EFC82'
    FILE_VERSION = 1
    iv = b'\xadH\xc3=\xa1\xa4\xfe\xfd'
    S = b'EFC82\x01\xadH\xc3=\xa1\xa4\xfe\xfd\xfa\xd2\x80\xce\xaeb4\xc6\xda\xd4\x93g\xfb\xbb[$\x9c=\x19V\xdfRa\x84x\x85\xe7(%+\xdc\xa5\x0e\x0b0\xa28\\\x15\x8f\x00\x00\x008\xab\x98\x05>:\xfc\x01\x85RC3^\xab \xebim\x16\x06\xf5h\xbaO\xb3He\xdaU\xe7hz\xd1\x92\x0b\x94_\xbf\x8c\xe0\x85L\xd9\x83e\xf5^\xbc\xac\x96\x94\x96\xf5\xfa<\\\x9a'
    
    random.seed('0427cb12119c11aff423b6333c4189175b22b3c377718053f71d5f37fd2a8f22')
    rnd = random.Random()
    user = "erism"
    ts_ms = s 
    rdata = str(random.getrandbits(256))
    seed = f"{user}_{ts_ms}_{rdata}"
    rnd.seed(seed)
    ephkey = bytes(rnd.getrandbits(8) for _ in range(32))
    
    encryptor = AES.new(ephkey, mode = AES.MODE_CTR, counter = Counter.new(64, prefix = iv))
    enc_res = S[-56:]
    res = encryptor.decrypt(enc_res)
    if DATA_MAGIC in res or b"midnight" in res:
        return res
    return None


def find_sol(args):
    H, M = args
    for j in range(0, 60):
        for k in range(0, 1000):
            s = "2021-02-09!" + "{0:02d}".format(H) + ":" + "{0:02d}".format(M) + ":" + "{0:02d}".format(j) + "." + "{0:03d}".format(k)
            x = trial(s)
            if x != None:
                return x
    return None

for H in tqdm(range(0, 24)):
    for M in range(0, 60, 12):
        pool = mp.Pool(12)
        params = [(H, M + i) for i in range(0, 12)]
        solutions = pool.map(find_sol, params)
        solutions = list(filter(None, solutions))
        if len(solutions) != 0:
            print(solutions[0])
        print(H, M)

