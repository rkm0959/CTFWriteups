from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string
import random as rd # avoid confusion with sage
import multiprocessing as mp
import itertools

from sage.rings.polynomial.multi_polynomial_sequence import PolynomialSequence

# defund is god
def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = PolynomialSequence([], f.parent())
	for i in range(m+1):
		power = (N ** (m-i)) * (f ** i)
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = power
			for variable, shift in zip(f.variables(), shifts):
				g *= variable ** shift
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)
	B = B.change_ring(ZZ)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in B*monomials:
		if h.is_zero():
			continue
		H.append(h.change_ring(QQ))
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			V = I.variety(ring=ZZ)
			if V:
				roots = []
				for root in V:
					root = map(R, map(root.__getitem__, f.variables()))
					roots.append(tuple(root))
				return roots

	return []


                                                                                                                          
n = 376347864369130929314918003073529176189619811132906053032580291332225522349124770927556541528827257242440708492473086949335591022991715583608318595770643139658398940858358366788472884935226392323475683663699450192657590965945792699658618476121298301964814904817629813971114882401961638885452623305901569855693667669                                                                                                                                               
e = 310766221758298615381202293330340201483059349618898159596286032329366528507960364515724537815587119639645241427449290559721282531962504187828968370246921804939126848756614691757878117709116273156365166616707032588454229002048939764035908902821773289938766897121298435864096976179239412103595971947786698704390414999
enc = 303959676149267585825046248298946771045524761540948385119310381022731003152171453295355624619013005255259014408962058282203132797411290952180380162699236575669681289832696809724483816916203823843359489329046259936011464869397208487809073597880729992617105037777911285154649450892121090200338517719744860831555514222

def solver(A, B, C, T):
    # Ax^2 + Bx + C = T
    cc = (-B + isqrt(B * B - 4 * A * (C - T))) // (2 * A)
    return cc

alp = 1337
bet = 2021

p_small = solver(alp * bet, alp << 300, 0, n) * 1337
p_large = solver(alp * bet, bet << 300, 0, n) * 1337 + (1 << 300)

tot_small = p_large + (n // p_large)
tot_large = p_small + (n // p_small)

delt = tot_large - tot_small

d_tilde = (1 << 376)
phi_approx = n + 1 - tot_small

bound_1 = (1 << 377)
bound_2 = delt

P = PolynomialRing(Integers(e), 'x, y')
x, y = P.gens()
f = x * (phi_approx - y) + 1

X, Y = small_roots(f, (bound_1, bound_2), m=3, d=4)[0]
phi = int(phi_approx) - int(Y) 
d = inverse(int(e), int(phi))
print(long_to_bytes(pow(enc, d, n)))
