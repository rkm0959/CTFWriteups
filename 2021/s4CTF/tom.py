from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
from os import urandom
import multiprocessing as mp
from sympy.ntheory.modular import solve_congruence

def isOk(x):
    F = list(factor(x))
    ans = 0
    for res in F:
        ans += res[1]
    if ans == 2:
        return True
    return False 

def tom(n):
    c = (n % 2) ^ 1 
    while True:
        FU = n + c
        FD = n - c
        if isOk(FU) == True:
            return c
        if isOk(FD) == True:
            return c
        c += 2

def kthp(n, k):
	if n == 0:
		return 0
	lef = 1
	rig = 2
	best = 0
	while rig ** k < n:
		rig = rig << 1
	while lef <= rig:
		mid = (lef + rig) // 2
		if mid ** k <= n:
			best = mid
			lef = mid + 1
		else:
			rig = mid - 1
	return best

# solve1 ~ solve3 : rbtree's work

def solve3(L, R, v, tr=1000000):
    for _ in range(tr):
        p = getPrime(L.bit_length() // 2 + 1)
        q = getPrime(L.bit_length() // 2 + 1)

        if not(L <= p * q <= R):
            continue

        n = p * q
        if tom(n - v) == v:
            return n - v
        if tom(n + v) == v:
            return n + v
    return None

def solve2(L, R, v, tr=100000):
    for v in [31, 29, 23, 19, 17, 13, 11, 7, 5, 3]:
        if t % v == 0:
            break
    else:
        return None

    for _ in range(tr):
        while True:
            p = next_prime(rand.randint(L // v, R // v))
            q = next_prime(p)

            if q - p == 2 * (t // v):
                break

        n = v * (int(p + q) // 2)

        if tom(n) == t:
            return n
    return None

def solve1(L, R, v, tr=100000):
    for a in range(1, 30):
        for b in range(2 if a % 2 else 1, 30, 2):
            for l in range(-30, 30):
                for _ in range(tr):
                    if l**2 * a + l * b != 2 * t:
                        continue
                    
                    for __ in range(100):
                        p = next_prime(rand.randint(kthp(L // a, 2), kthp(R // a, 2)))
                        if isPrime(a * p + b):
                            break
                    
                    if not isPrime(a * p + b):
                        continue
                    
                    q = a * p + b
                    v1 = p * q
                    v2 = (p - l) * (q + l * a)

                    n = (v1 + v2) // 2
                    if L <= n <= R and tom(n) == t:
                        return n


# rkm0959's work

def find_sol(args):
    L, R, v = args
    for i in range(300):
        p = getPrime(L.bit_length() // 2 + 1)
        q = getPrime(L.bit_length() // 2 + 1)
        n = p * q + v
        isok = True
        for i in range(-v+2, v, 2):
            if isOk(n+i) == True:
                isok = False
                break
        if isok == True and L < n < R:
            return n

def CRT(a, m, b, n):
	(u, v) = solve_congruence((a, m), (b, n))
	return u, v

def get_prime(args):
    START, EN, c1, c2 = args
    for i in range(7500):
        if START + i > EN:
            return None
        res = c2 * (START + i) + c1
        if isPrime(res):
            return res
    return None

def find_sol1(args):
    L, R, c1, c2, v, mark, CNT = args
    ccc = 0
    cur = 0
    LEFT = (L // 3 + 2 - c1) // c2 + 1
    RIGHT = (R // 3 - 2 - c1) // c2 - 1
    while True:
        pool = mp.Pool(12)
        p = 0
        Found = False
        while True:
            if Found == True:
                break
            params = [(LEFT + cur * 90000 + 7500 * i, RIGHT, c1, c2) for i in range(12)]
            for result in pool.imap_unordered(get_prime, params):
                if result != None:
                    p = result
                    Found = True
                    break
            cur += 1
            print(cur * 90000)
        LEFT = (p - c1) // c2 + 1
        n = 3 * p + v
        print(L < n < R)
        isok = True
        idx = 0
        for i in range(-v+2, v, 2):
            if CNT[idx] >= 2:
                idx += 1
                continue
            if mark[idx] != 0:
                if (n + i) // mark[idx] in Primes():
                    isok = False
                    break
            if mark[idx] == 0 and isOk(n+i) == True:
                isok = False
                break
            idx += 1
        if isok == True and L < n < R:
            return n

def solve(L, R, v):
    if R <= 11 ** 16:
        pool = mp.Pool(12)
        cnt = 0
        while True:
            params = [(L, R, v) for _ in range(12)]
            for result in pool.imap_unordered(find_sol, params):
                if result != None:
                    return result
            cnt += 1
            print(3600 * cnt)
    elif R <= 11 ** 45:
        lst = [i for i in range(3, 100) if isPrime(i)]
        ass = [0] * len(lst)
        ass[0] = 1
        RG = [i for i in range(2, 2*v, 2)]
        mark = [0 for i in range(2, 2*v, 2)]
        CNT = [0 for i in range(2, 2*v, 2)]
        cur = (0, 1)
        for i in range(len(mark)):
            if RG[i] % 3 == 0:
                mark[i] = 3
                CNT[i] += 1
        for i in range(len(mark)):
            if mark[i] == 0:
                p = 0
                for j in range(len(lst)):
                    if ass[j] != 1 and RG[i] % lst[j] != 0:
                        ass[j] = 1
                        p = lst[j]
                        break
                if p != 0:
                    for j in range(len(mark)):
                        if RG[j] % p == RG[i] % p:
                            mark[j] = p
                            CNT[j] += 1
                    cur = solve_congruence(cur, ((p - RG[i]) % p, p))
            if cur[1] > R // (10 ** 11):
                break
        for i in range(len(mark)):
            if cur[1] > R // (10 ** 11):
                break
            if CNT[i] == 1:
                p = 0
                for j in range(len(lst)):
                    if ass[j] != 1 and RG[i] % lst[j] != 0:
                        ass[j] = 1
                        p = lst[j]
                        break
                if p != 0:
                    for j in range(len(mark)):
                        if RG[j] % p == RG[i] % p:
                            mark[j] = p
                            CNT[j] += 1
                    cur = solve_congruence(cur, ((p - RG[i]) % p, p))
        A, B = cur
        cc = A * inverse(3, B)
        cc %= B
        print(B)
        print(mark)
        print(CNT)
        return find_sol1((L, R, cc, B, v, mark, CNT))

'''
ANS = [0] * 45
for c in range(18, 40):
    ANS[c] = solve(11 ** c, 11 ** (c+1), 20 + c - 5)
    print(ANS)
'''

ANS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5696194220880773646, 251981759579848588327, 1154032885276102912118, 9092403532672744914669, 87023047755254288277640, 950476713962543219792381, 10636271134169006814778332, 212335884459019522359238123, 2024556171465148234689075344, 13109994307810399851142331085, 202498690367630759459787349966, 2025276206044112497739973249587, 18577577073235503567108251737398, 1491132482426872468955714873810929, 2434444489853247801032462355436490, 49451961785448087233639474718054591, 257211218139865373514655833854866372, 4254371540565061688785135622323624853, 55181433034444696830114747883117978314, 399815587302009273783510471442964210395, 3788470107391407223670451266619996506486, 43042617873544094894268609447398502892827, 0, 0, 0, 0, 0]

# rbtree's work, modified
while True:
    try:
        r = remote('198.211.127.76', 7027)
        c = 4
        while c < 40:
            print(c)
            L, R = 11**c, 11**(c+1)
            r.recvuntil('tom(n) =')
            t = int(r.recvuntil('\n').strip())
            n = None 
            if c >= 18:
                n = ANS[c] - (20 + c - 5) + t
            if not n and c >= 18:
                print("Solve0")
                n = solve(L, R, t)
            if not n and c >= 10:
                print("Solve1")
                n = solve1(L, R, t, 7)    
            if not n:
                print("Solve2")
                n = solve2(L, R, t, 200)
            if not n:
                print("Solve3")
                n = solve3(L, R, t, 50)
            if not n:
                print("Solve0")
                n = solve(L, R, t)
            r.sendline(str(n))
            print("SENT!")
            c += 1
            print(r.recvline())
    except EOFError:
        r.close()
        continue
    r.close()
    break
