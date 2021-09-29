from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Cipher import AES, ARC4, DES

def inthroot(a, n):
    return a.nth_root(n, truncate_mode=True)[0]

n, e = (5943169364392579648240628105465400265561630477719849140342288893646282358845864829196464904298425034495515703590715696166689341849788423790118035115884268058450057766891418761627136386260375534474238287294722575087291704432681906513559934960801746158191355141430407698622886747610818853554584519369492697299961587570531415598410602926850787615266600194130088653542080297272898142822126215764285317511778718862825024939241749996811603610592132845393755564618871967716819173935553139267269362451423802419847919801412517294612793840767037662589233422389282092051866024514599213445596030685325227269609799, 1762727270442607836236621349004505613506359415168929966540357011133047321101203605340201016757203407375680206339341465088639129039278027484128644822299382121442456525803635369125157261704416172232695058332167310707999473221769390010733123910955508477009411113166141188309425895082608534271594076218827)
dpmask, dqmask = (1361, 1475)
enc = 4531542437692818645025309324015912433184165181252393791711464775823247402127139569010657935303362440253951226047224610112010632226435610975118324658493911658016955717228741291266124372004503735693124810068041692730706167827666860062121413284053921548345924563903211959003376490264228814415500106847482893238907846512437694006785527867729127228361388592714377847012086312471372061723017560705890925568994607972832373362380226566506368932968108567819188587148829190811891555283157485379418388715910299951228404648535235675640369275644493614250037857212768450860647393276921502407057557208885073276533644


print(e.bit_length())
print(n.bit_length())
r = Integer(n) / Integer(e * e)
c = continued_fraction(r)

for i in range(100):
    uu = c.numerator(i)
    vv = c.denominator(i)
    if int(uu).bit_length() > 200:
        break
    for g in range(1, 20, 2): # nice!
        u = g * uu
        v = g * vv
        if int(u) % (1 << 12) == (dpmask * dqmask) % (1 << 12):
            dpdq = int(u)
            kl = int(v)
            print(dpdq)
            print(dpdq.bit_length())
            dvs = divisors(dpdq)
            for x in dvs:
                if x % (1 << 12) == dpmask:
                    dp = x
                    dq = dpdq // x
                    dvdvs = divisors(kl)
                    for y in dvdvs:
                        if (e * dp - 1) % y == 0 and y > (1 << 50):
                            k = y
                            l = kl // k
                            p = (e * dp - 1) // k + 1
                            q = (e * dq - 1) // l + 1 

                            if isPrime(p) and isPrime(q):
                                phi = (p-1) * (q-1)

                                d = inverse(e, phi)

                                print(long_to_bytes(pow(enc, d, n)))
