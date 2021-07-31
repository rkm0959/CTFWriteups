from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa


r = remote('05.cr.yp.toc.tf', 14010)

def read_lines(num = 5):
    for _ in range(num):
        r.recvline()

def get_report(m1, m2):
    read_lines()
    r.sendline("R")
    r.recvline()
    r.sendline(str(m1) + "," + str(m2))
    print(r.recvline())

def get_params():
    read_lines()
    r.sendline("G")
    s = r.recvline().split()
    v = int(s[-1][:-1])
    f = int(s[-2][:-1])
    n = int(s[-3][1:-1])
    return n, f, v

def improved(m, params):
	n, f, v = params
	if 1 < m < n**2 - 1:
		e = pow(m, f, n**2)
		u = divmod(e-1, n)[0]
		L = divmod(u*v, n)[1]
	H = hashlib.sha1(str(L).encode('utf-8')).hexdigest()
	return H

read_lines()
n, f, v = get_params()
m = pow(2, n+1, n* n)
get_report(2, m)