from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
import multiprocessing as mp
from sage.modules.free_module_integer import IntegerLattice


def apply_permutation(init, perm):
    res = [0] * 52
    for i in range(0, 52):
        res[i] = init[perm[i]]
    return res


perm1 = [0] + [i+1 for i in range(1, 51)] + [1]
perm2 = [1, 2, 0] + [i for i in range(3, 52)]

r = remote("cards.zajebistyc.tf", 17004)

payload = ""
for i in perm1:
    payload += str(i) + "\n"

r.sendafter("\n", payload)

payload = ""
for i in perm2:
    payload += str(i) + "\n"

r.send(payload)

r.recvuntil(": ")


START = [i for i in range(52)]

def PERM1():
    global START
    START = apply_permutation(START, perm1)
    r.sendline("a")

def PERM2():
    global START
    START = apply_permutation(START, perm2)
    r.sendline("b")

# (0, k+1, k+2)
def swap_adjacent1(k):
    for i in range(k):
        PERM1()
    PERM2()
    for i in range(51-k):
        PERM1()

# (0, k+2, k+1)
def swap_adjacent2(k):
    swap_adjacent1(k)
    swap_adjacent1(k)

# (1, 2, k+1)
def swap_12(k):
    swap_adjacent1(k)
    PERM2()
    if k != 50:
        swap_adjacent2(k)

# (1, x, y)
def swap_1xy(x, y):
    if x == 2:
        swap_12(y - 1)
        return
    if y == 2:
        swap_12(x - 1)
        swap_12(x - 1)
        return
    swap_12(y - 1)
    swap_12(x - 1)
    swap_12(x - 1)

# (x, y, z)
def swapp(x, y, z):
    swap_1xy(x, y)
    swap_1xy(y, z)


for IDX in range(52):
    s = r.recvline()
    print(s)
    random_list = s.split(b" ")
    if IDX == 0:
        TARGET = [int(i) for i in random_list]
    if IDX >= 1:
        TARGET = [int(i) for i in random_list[4:]]

    idx = START.index(TARGET[0])
    if idx == 1:
        swap_adjacent2(0)
    if idx == 2:
        swap_adjacent1(0)
    if idx >= 3:
        swap_12(idx - 1)
        swap_adjacent2(0)

    idx = START.index(TARGET[1])

    if idx == 2:
        swap_12(2)
        swap_12(2)
    if idx >= 3:
        swap_12(idx - 1)
        swap_12(idx - 1)


    for i in range(2, 50):
        print(i)
        idx = START.index(TARGET[i])
        if i == idx:
            continue
        if idx != 51:
            swapp(i, idx, 51)
        else:
            swapp(i, idx, 50)
    print(START)
    print(TARGET)


print(r.recvline())
print(r.recvline())
