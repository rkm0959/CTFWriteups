from sage.all import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, inverse, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import * 
import random as rand
from tqdm import tqdm


conn = remote("03.cr.yp.toc.tf", 17331)

'''
def pow_d(g, e, n):
	t, r = 0, 1
	for _ in bin(e)[2:]:
		if r == 4: t += 1
		r = pow(r, 2, n)
		if _ == '1': r = r * g % n
	return t, r
'''

p = Integer(2 ** 1024 - 2 ** 234 - 2 ** 267 - 2 ** 291 - 2 ** 403 - 1)
p1 = (p - 1) >> 1
F = GF(p)
four = F(4)
two = F(2)
for i in range(3):
    conn.recvline()


def get_result():
    s = conn.recvline().strip()
    try:
        t = int(s.split()[-2][1:-1])
        return t
    except:
        print(s)

def get_root(t):
    if t % 2 == 1:
        d = inverse(t, p - 1)
        return four ** d
    else:
        d = inverse(t >> 1, p1)
        return two ** d

def get_root_2(t):
    d = inverse(t, p1)
    return two ** d

cur_start = 1
for i in tqdm(range(1026)):
    if i >= 1020:
        for _ in range(3):
            conn.recvline()
        conn.sendline(b"t")

        g0 = get_root(cur_start)
        conn.recvline()
        conn.sendline(str(g0).encode())
        t0 = get_result()

    g0 = get_root_2(cur_start)
    conn.sendlines([b"t", str(g0).encode()])
    conn.recvlines(4)

    t0 = get_result()

    if t0 >= 1:
        cur_start = 2 * cur_start
    else:
        cur_start = 2 * cur_start + 1

