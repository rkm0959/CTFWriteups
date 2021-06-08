from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
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

def calc_idx(x):
    # (i+j)(i+j+1) + 2j = 2x
    # (i+j)^2 + i+j + 2j = 2x
    if x < 256:
        return [x]
    # (i+j)^2 < 2x
    v = kthp(2 * x, 2)
    for tot in [v-3, v-2, v-1, v]:
        tt = 2 * x - tot * tot - tot
        if tt % 2 == 0 and tt >= 0:
            j = tt // 2
            if 0 <= j <= tot:
                return calc_idx(tot - j) + calc_idx(j)



fin = 2597749519984520018193538914972744028780767067373210633843441892910830749749277631182596420937027368405416666234869030284255514216592219508067528406889067888675964979055810441575553504341722797908073355991646423732420612775191216409926513346494355434293682149298585

print(bytes(calc_idx(fin)))
