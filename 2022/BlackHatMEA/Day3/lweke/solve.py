from secrets import randbelow
import os, base64, hashlib
from Crypto.Util.number import getPrime, isPrime 
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from sage.all import *
from tqdm import tqdm
from pwn import *


def prevprime(x):
    i = 1
    while True:
        if isPrime(x - i):
            return x - i
        i += 1 

# -N/2 ~ N/2 vector of size N
def gen_vec(N):
    return [randbelow(N) - N // 2 for _ in range(N)]

# N x N vector, < Q
def gen_mat(N, Q):
    return [[randbelow(Q) for _ in range(N)] for _ in range(N)]

# a * A + b * B + c mod Q 
def mat_add(A, B, Q, a=1, b=1, c=0):
    return [[(a * A[i][j] + b * B[i][j] + c) % Q for j in range(len(B))] for i in range(len(A))]

# c * A * B mod Q
def mat_mul(A, B, Q, c=1):
    return [[sum((c * A[i][j] * B[j][k]) % Q for j in range(len(B))) % Q for k in range(len(A))] for i in range(len(A))]

# c * A * B mod Q's diagonal
def mat_dia(A, B, Q, c=1):
    return [sum((c * A[i][j] * B[j][i]) % Q for j in range(len(B))) % Q for i in range(len(A))]

# Encoding matrix -> base64
def enc_mat(A):
    byt = b"".join(bytes.fromhex(''.join('{:07x}'.format(j) for j in i)) for i in A)
    return base64.urlsafe_b64encode(byt).decode()

# Decoding base64 -> matrix
def dec_mat(A):
    hx = base64.urlsafe_b64decode(A).hex()
    rs = [hx[i:i + 7*128] for i in range(0, len(hx), 7*128)]
    return [[int(i[j:j + 7], 16) for j in range(0, len(i), 7)] for i in rs]

# s -> hex
def enc_sig(s):
    return int(''.join(str(i) for i in s),2).to_bytes(128//8, 'big').hex()

def transpose(M):
    ret = [[0] * 128 for i in range(128)]
    for i in range(128):
        for j in range(128):
            ret[i][j] = M[j][i]
    return ret 

url = "blackhat4-401e1c5f2c1f3a73486cb8bd708ed1fa-0.chals.bh.ctf.sa"

conn = remote(url, 443, ssl=True, sni=url)
Q = 268435399

cands = [set() for _ in range(128)]

conn.recvlines(13)

print(conn.recvline()) # domain parameter

enc_M = conn.recvline().split()[-1]

M_real = dec_mat(enc_M)

CC = Matrix(GF(Q), 128, 128)

for i in range(128):
    for j in range(128):
        CC[i, j] = M_real[j][i]

conn.recvlines(2)

encrypted_flag_hex = conn.recvline().split()[-1].decode()
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
iv = encrypted_flag[:16]
ctxt = encrypted_flag[16:]


print(conn.recvline()) # let's shake hands

it = 0
while True:
    it += 1
    print("it", it)

    conn.recvlines(2)
    # send pubkey
    pA = gen_mat(128, Q)
    send_pA = enc_mat(pA)
    conn.sendline(send_pA)

    print(1, conn.recvline()) # "\n"
    print(2, conn.recvline()) # here's my part

    pB_enc = conn.recvline().split()[-1]
    pB = dec_mat(pB_enc)
    conn.recvline() # sg
    conn.recvline() # tag

    for i in range(128):
        if len(cands[i]) == 1:
            continue
        for j in range(128):
            cand_init = set()
            for k in range(-126, 130, 2):
                cand_init.add((pB[i][j] + k) % Q)
            if len(cands[i]) == 0:
                cands[i] = cand_init
            else:
                cands[i] = cands[i].intersection(cand_init)
    
    cont = False

    for i in range(128):
        if len(cands[i]) != 1:
            cont = True
    if cont == False:
        break

fin_ok = []
for i in range(128):
    fin_ok.append(list(cands[i])[0])


T_M = Matrix(GF(Q), 128, 128)
for i in range(128):
    for j in range(128):
        T_M[i, j] = fin_ok[i]
    


sk_fin = CC ** (-1) * T_M

fin_sk = [0] * 128

for i in range(128):
    fin_sk[i] = int(sk_fin[i, 0])
    if fin_sk[i] > 300:
        fin_sk[i] -= Q

act_sk = [[0] * 128 for _ in range(128)]
for i in range(128):
    for j in range(128):
        act_sk[i][j] = fin_sk[i]

key = hashlib.sha256(str(act_sk).encode()).digest()

flag_final = AES.new(key, AES.MODE_CBC, iv).decrypt(ctxt)

print(flag_final)