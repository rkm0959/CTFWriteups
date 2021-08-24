def bxor(ba1,ba2):
	return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

BITS = 128
SHARES = 30

poly = [rand.getrandbits(BITS) for _ in range(SHARES)]
flag = open("flag.txt", "rb").read()

rand.seed(poly[0])

res = bxor(flag, long_to_bytes(rand.getrandbits(len(flag)*8)))

x = (1 << 128)
query = sum(map(lambda i: poly[i] * pow(x, i), range(len(poly))))

poly_0 = query % (1 << 128)

rand.seed(poly[0])

flag = bxor(res, long_to_bytes(rand.getrandbits(len(flag)*8)))

print(flag)

# rarctf{n3v3r_trust_4n_1nt3g3r_d124d204}