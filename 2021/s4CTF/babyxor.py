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

f = open('flag.enc', 'rb')
s = f.read()


print(len(s))

for i in range(256):
    flag = bytes([i])
    for j in range(42):
        flag += bytes([flag[-1] ^ s[j]])
    print(flag)
