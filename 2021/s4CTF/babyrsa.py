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

pkey = 48564396752059338791464352725210493148212425902751190745668164451763507023284970474595680869078726765719920168392505794415687815488076204724659643390252172928332322944711949999326843460702414647825442748821062427474599006915155109396213406624079900714394311217571510958430682853948004734434233860146109894977
enc = 28767981118696173499362412795754123415661648348744243377735885542432968964926551295510845917978847771440173910696607195964650864733310997503291576565605508828208679238871651079005335403223194484223700571589836641593207297310906538525042640141507638449129445170765859354237239005410738965923592173867475751585

e = 31337

# P = p * 10^k + q
# Q = q * 10^k + p

var('p, q')

for k in [77, 78]:
    # pq (10^2k + 1) + (p^2 + q^2) 10^k = pkey 
    sqsum = (pkey * inverse(10 ** k, 10 ** (2 * k) + 1) ) % ((10 ** (2 * k)) + 1)
    for i in range(1, 5):
        sqsum += (10 ** (2 * k)) + 1
        if sqsum > (2 ** 513):
            break
        pq = (pkey - 10 ** k * sqsum) // (10 ** (2 * k) + 1)
        tot = kthp(sqsum + 2 * pq, 2)
        dif = kthp(sqsum - 2 * pq, 2)
        p = (tot + dif) // 2
        q = (tot - dif) // 2
        if isPrime(p) and isPrime(q):
            P = int(str(p) + str(q))
            Q = int(str(q) + str(p))
            phi = (P - 1) * (Q - 1)
            d = inverse(e, phi)
            print(long_to_bytes(pow(enc, d, pkey)))
            exit()