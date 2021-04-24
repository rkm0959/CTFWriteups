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

def is_ascii(s):
	return all(32 <= c < 128 for c in s)

A = 844298886536102102829429887239442280531833016184944310667136996459156918746405824828816678218599392201232600192410066055059804298579937332814877553581599184247404
B = 468537588442373918531086438736512221547939545041235667415870300706375550653375662041142909124331906341047098854068053691093683234579835326888942621717466998635211
C = 844298886536102102829429887239442280531833016184944310667136996459156918746405825386446222977715112808855904143526125215759285866282041700190923770523214222144611

dif = C - A 
tot = B // dif 
c_1 = (tot - dif) // 2
c_2 = (tot + dif) // 2

n = kthp(A - c_1, 2)

assert n ** 2 + c_1 == A
assert c_2 ** 2 - c_1 ** 2 == B
assert n ** 2 + c_2 == C

p = 28312905903414733214096354352151962531937
q = 32453658557333630932034374992046016455903

for x in range(p-1, 0, -1):
    print(p - x)
    if isPrime(x):
        break
    B = long_to_bytes(x)
    if is_ascii(B) == False:
        continue
    for y in range(q-1, 0, -1):
        if isPrime(y):
            break
        C = long_to_bytes(y)
        if is_ascii(C) == False:
            continue
        m_1 = x + int(sqrt(y))
        m_2 = y + int(sqrt(x))
        if pow(m_1, 65537, n) == c_1 and pow(m_2, 65537, n) == c_2:
            print(B + C)

