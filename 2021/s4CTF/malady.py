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

'''
make_matrix : makes element in GL2 Zn

bpow : P^(2^n)

make_keypair : if QP^-1 != PQ
B = Q^-1P^-1Q
J = Q^r 

pub : n, P, B, J
priv : Q

enc : D = J^s
E = D^-1 P D
K = D^-1 B D
U = message matrix
V = K U K

ciphertext = V, E
'''

pubkey =  (2419329577094580148790320061829248654877619, [[1181968185527581745853359689584528732855897, 153406550412853584463306785000418170296859],
[1454322498540966456231711148502103233345812, 1654517770461057329449871572441944497585269]], [[1268457653971486225679848441105472837265167, 579420771722577779695828127264001257349949],
[2351869917091027496266981633084389584522183,  450983777743266243622871312465133743097962]], [[2358538357277340167153980348659698938509404,  365220208942190647616618122919911425848374],
[  47691648572918059476944115452005044039782, 1236869052280934587487352533961953209955284]])
enc =  ([[ 425149944883810928331948322693601721947824, 1442606353540488031613587882680057605691721],
[2270690430439772938430962982653361813264189, 1607654191517170510458852398046623728536109]], [[ 177396832593088516072893113015799710489963, 2001682469448750676325856357286302774486863],
[   5338037289866014093970785328310590783999,  239759546300970410440018087181424865073584]])

n, P, B, J = pubkey
V, E = enc 

p = 1238174842774708106839
q = 1953948257964072406021

B = Matrix(Zmod(n), B)
V = Matrix(Zmod(n), V)
P = Matrix(Zmod(n), P)
J = Matrix(Zmod(n), J)
E = Matrix(Zmod(n), E)

'''
s = -1
DICT = {}

for i in tqdm(range(0, 1<<16)):
    res = J ** (i * (1 << 16)) * E * J ** (- (i * (1 << 16)))
    CC = str(res[0, 0]) + str(res[0, 1]) + str(res[1, 0]) + str(res[1, 1])
    DICT[CC] = i

for i in tqdm(range(0, 1<<16)):
    res = J ** (-i) * P * J ** i 
    CC = str(res[0, 0]) + str(res[0, 1]) + str(res[1, 0]) + str(res[1, 1])
    if CC in DICT.keys():
        s = i + DICT[CC] * (1 << 16)

print(s)
'''


s = 2662202897
D = J ** s 
K = D ** -1 * B * D 
U = K ** -1 * V * K ** -1

res_0 = str(int(U[0, 1]))
res_1 = str(int(U[0, 0]))
res_2 = str(int(U[1, 1]))
res_3 = str(int(U[1, 0]))

print(len(res_0))
print(len(res_1))
print(len(res_2))
print(len(res_3))
flag = res_0 + '0' +  res_1 + res_2 + res_3 
flag = int(flag)

print(long_to_bytes(flag))