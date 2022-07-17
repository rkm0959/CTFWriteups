from sage.all import *
from pwn import * 
from tqdm import tqdm 
from Crypto.Util.number import inverse

conn = remote("127.0.0.1", 9003)

conn.recvline()
s = conn.recvline().rstrip().decode()
assert len(s) == 16

for i in tqdm(range(1 << 26)):
    t = str(i)
    hash = hashlib.sha256((s + t).encode()).hexdigest()
    if hash[:6] == "000000":
        conn.sendline(t.encode())
        break

e = 293
n = int(conn.recvline())
k_p, k_q = 0, 0

dp_perm = conn.recvline().strip().decode()[::-1]
dq_perm = conn.recvline().strip().decode()[::-1]
dp_list = []

for x in dp_perm:
    dp_list.append(int(x, 16))
dq_list = []

for x in dq_perm:
    dq_list.append(int(x, 16))

def work(ps, qs, dps, dqs, perms, cur):
    if cur == 257:
        return
    
    nxtps = []
    nxtqs = []
    nxtdps = []
    nxtdqs = []
    nxtperms = []

    for p, q, dp, dq, perm in zip(ps, qs, dps, dqs, perms):
        if cur >= 250:
            if p * q == n:
                conn.sendline(str(p).encode())
                conn.sendline(str(q).encode())
                print(conn.recvline())
                exit()
        if cur == 256:
            continue
        
        val_1 = ((n - p * q) >> (4 * cur)) % 16 # qp_i + pq_i
        val_2 = ((k_p * p - k_p + 1 - e * dp) >> (4 * cur)) % 16 # e dp_i - k_p p_i
        val_3 = ((k_q * q - k_q + 1 - e * dq) >> (4 * cur)) % 16 # e dq_i - k_q q_i
        
        for pi in range(16):
            qi = 0
            if cur == 0 and pi % 2 == 0:
                continue 
            if cur == 0:
                qi = ((n % 16) * inverse(pi, 16)) % 16
            if cur >= 1:
                qi = ((val_1 - (q % 16) * pi) * inverse(p % 16, 16)) % 16
            
            dp_i = (inverse(e, 16) * (k_p * pi + val_2)) % 16
            dq_i = (inverse(e, 16) * (k_q * qi + val_3)) % 16
            
            if perm[dp_list[cur]] != -1 and perm[dp_list[cur]] != dp_i:
                continue 
            if perm[dq_list[cur]] != -1 and perm[dq_list[cur]] != dq_i:
                continue
            if perm[dp_list[cur]] != dp_i and dp_i in perm:
                continue
            if perm[dq_list[cur]] != dq_i and dq_i in perm:
                continue 
            
            on_p = False
            on_q = False 
            
            if perm[dp_list[cur]] == -1:
                on_p = True 
                perm[dp_list[cur]] = dp_i
            if perm[dq_list[cur]] == -1:
                on_q = True 
                perm[dq_list[cur]] = dq_i 
            
            nxtps.append(p + (pi << (4 * cur)))
            nxtqs.append(q + (qi << (4 * cur)))
            nxtdps.append(dp + (dp_i << (4 * cur)))
            nxtdqs.append(dq + (dq_i << (4 * cur)))
            nxtperms.append(copy(perm))
            
            if on_p:
                perm[dp_list[cur]] = -1
            if on_q:
                perm[dq_list[cur]] = -1
    
    work(nxtps, nxtqs, nxtdps, nxtdqs, nxtperms, cur + 1)

for idx in tqdm(range(1, e)):
    if (idx * (n - 1) + 1) % e == 0:
        continue 
    k_p = idx 
    k_q = ((1 - k_p) * inverse(k_p * n - k_p + 1, e)) % e
    work([0], [0], [0], [0], [[-1] * 16], 0)