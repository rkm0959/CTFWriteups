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
import itertools
from sage.all import *
from sage.modules.free_module_integer import IntegerLattice

# https://sci-hub.se/https://doi.org/10.1017/S000497270003207X
# LATTICE BASIS REDUCTION, JACOBI SUMS AND HYPERELLIPTIC CRYPTOSYSTEMS

p = 1766847064778384459845418474343475078494849781773959418746556895625158061
RR = RealField(2000)

a = Integer(GF(p)(2) ** ((p-1)//5))
M = Matrix(ZZ, 4, 4)
MUL = 10 ** 400
M[0, 0] = p * MUL
M[0, 2] = p * MUL
for idx in range(1, 4):
    tt_real = (2/5 * idx * pi).cos() - Integer(GF(p)(a) ** idx)
    tt_imag = (2/5 * idx * pi).sin()
    M[idx, 0] = RR(tt_real * MUL).round()
    M[idx, 1] = RR(tt_imag * MUL).round()
    tt_real = (2/5 * 2 * idx * pi).cos() - Integer(GF(p)(a) ** idx)
    tt_imag = (2/5 * 2 * idx * pi).sin()
    M[idx, 2] = RR(tt_real * MUL).round()
    M[idx, 3] = RR(tt_imag * MUL).round()

B = M.LLL()

v = vector(B[0])
CC = M.transpose().solve_right(v)
val_0 = p * CC[0] - Integer(GF(p)(a) ** 1) * CC[1] - Integer(GF(p)(a) ** 2) * CC[2] - Integer(GF(p)(a) ** 3) * CC[3]
val_1 = CC[1]
val_2 = CC[2]
val_3 = CC[3]

# beta = val_0 + val_1 * zeta5 + val_2 * zeta5 ** 2 + val_3 * zeta5 ** 3

F = CyclotomicField(5, 'x')
x = F.gen()

res = val_0 + val_1 * x + val_2 * x * x + val_3 * x * x * x
rest = val_0 + val_1 * (x ** 2) + val_2 * (x ** 4) + val_3 * (x ** 6)
resp = val_0 + val_1 * (x ** 3) + val_2 * (x ** 6) + val_3 * (x ** 9)
resr = val_0 + val_1 * (x ** 4) + val_2 * (x ** 8) + val_3 * (x ** 12)

Jst = res * resp


A = list(Jst)[3]
B = list(Jst)[2]
C = list(Jst)[1]
D = list(Jst)[0]


Jst = -Jst
Jst = x * Jst

Jac = Jst + 1

A = list(Jac)[3]
B = list(Jac)[2]
C = list(Jac)[1]
D = list(Jac)[0]

U = A * (x ** 3) + B * (x ** 2) + C * x + D
V = A * (x ** 6) + B * (x ** 4) + C * (x ** 2) + D
W = A * (x ** 9) + B * (x ** 6) + C * (x ** 3) + D
T = A * (x ** 12) + B * (x ** 8) + C * (x ** 4) + D

res = U * V * W * T
res = Integer(res)


def alien_prime(a):
    p = (a ** 5 - 1) // (a - 1)
    assert is_prime(p)
    return p


def encrypt_flag():
    e = 2873198723981729878912739
    Px = int.from_bytes(flag, 'big')
    P = C.lift_x(Px)
    JP = J(P)
    return e * JP


def transmit_point(P):
    mumford_x = P[0].list()
    mumford_y = P[1].list()
    return (mumford_x, mumford_y)

enc_x = [1276176453394706789434191960452761709509855370032312388696448886635083641, 989985690717445420998028698274140944147124715646744049560278470410306181, 1]
enc_y = [617662980003970124116899302233508481684830798429115930236899695789143420, 429111447857534151381555500502858912072308212835753316491912322925110307]

a = 1152921504606846997
alpha = 1532495540865888942099710761600010701873734514703868973
p = alien_prime(a)

FF = FiniteField(p)
R = PolynomialRing(FF, 'x')
x = R.gen()

h = 1
f = alpha * (x ** 5)


C = HyperellipticCurve(f,h,'u,v')
J = C.jacobian()
J = J(J.base_ring())

U = enc_x[0] + enc_x[1] * x + enc_x[2] * x * x
V = enc_y[0] + enc_y[1] * x

P = J((U, V))

e = 2873198723981729878912739
d = inverse_mod(e, res)
d = int(d)


val = p - list((d*P)[0])[0]
val = int(val)
print(long_to_bytes(val))
