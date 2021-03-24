abox = [
	[0xb, 0xc, 0xd, 0xe, 0xf, 0x0, 0x1, 0x2],
	[0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0],
	[0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf],
	[0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd],
	[0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe],
	[0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa],
	[0xf, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6],
	[0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0, 0x1],
	[0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb],
	[0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9],
	[0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7],
	[0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc],
	[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8],
	[0xd, 0xe, 0xf, 0x0, 0x1, 0x2, 0x3, 0x4],
	[0xc, 0xd, 0xe, 0xf, 0x0, 0x1, 0x2, 0x3],
	[0xe, 0xf, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5],
]

def bitxor(a, b):
	tt = ""
	l = len(a)
	for i in range(0, l):
		if a[i] == b[i]:
			tt += "0"
		else:
			tt += "1"
	return tt

def perm(s, p):
	assert len(s) == len(p)
	return ''.join([s[p[i]] for i in range(len(p))])

def strxor(s1, s2):    
	return ''.join(chr(ord(a) ^ b) for a, b in zip(s1, s2))

def strfuckxor(s1, s2):    
	return [ord(a) ^ b for a, b in zip(s1, s2)]

def strstrxor(s1, s2):    
	return [ord(a) ^ ord(b) for a, b in zip(s1, s2)]

def pad(mystr, l):
	if len(mystr) % l != 0:
		mystr = mystr.ljust(l * (len(mystr) // l + 1), '*')
	return mystr

def prepare_key(key, l):
	assert len(key) == l

	bkey = [bin(c)[2:].zfill(8) for c in list(key)]

	arraykey = []
	for i in range(len(abox)):
		temp = []
		for j in range(len(abox[i])):
			k = abox[i][j]
			temp.append(bkey[k])
		join = ''.join(map(str, temp))
		arraykey.append(join)

	return arraykey

def encrypt(msg, pkey, l):
	MSG = [pad(msg, l)[l*i:l*(i + 1)] for i in range(len(pad(msg, l)) // l)]
	s = [0, 1, 2, 3, 4, 5, 6, 7]
	cipher = ''
	for msg in MSG:
		enc, key  = '', prepare_key(pkey, l)
		msg_b = [bin(ord(c))[2:].zfill(8) for c in str(msg)]
		msg_bL = [''.join(map(str, msg_b[:8]))]
		msg_bR = [''.join(map(str, msg_b[8:]))]
		for i in range(16):
			msg_bL.append(msg_bR[i])
			msg_xorkey = [int(msg_bL[i][_]) ^ int(msg_bR[i][_]) ^ int(key[i][_]) ^ (i % 2) for _ in range(len(msg_bR[i]))]
			msg_bR.append(''.join(map(str, msg_xorkey)))
		result = msg_bL[l - 1] + msg_bR[l - 1]
		B = [perm(result[i:i + 8], s) for i in range(0, len(result), 8)]
		for b in B:
			enc += chr(int(b, 2))
		cipher += enc
	r = chr(1)
	cipher = strxor(cipher + r * l, pkey * (len(cipher) // l + 1))
	return cipher


f = open("flag.enc", "rb")
s = f.read()
s = s.decode("utf-8")
sss = s
cc = []
for i in range(0, len(s)):
	cc.append(ord(s[i]))
print(cc)
s = bytes(cc)
print(s)
print(len(s))
f.close()

cnt = 0


def true_work(p, r):
	global s, sss
	l = 16
	keyf = strfuckxor(chr(r) * 16, s[-16:])
	pkey = bytes(keyf)
	# print(pkey)
	org = strxor(sss  + chr(r) * l, pkey * (len(s) // l))
	org = org[:-16]
	cipher = org
	msg = ""
	for SS in range(0, len(cipher), 16):
		keykey = prepare_key(pkey, 16)
		part = cipher[SS : SS+16]
		cc = [bin(ord(c))[2:].zfill(8) for c in part]
		cc = [perm(cc[i], p) for i in range(0, len(cc))]
		result = ""
		for t in cc:
			result += t
		if len(result) != 128:
			return
		msg_bl = [''] * 16
		msg_br = [''] * 16
		msg_bl[15] = result[:64]
		msg_br[15] = result[64:]
		for i in range(14, -1, -1):
			msg_bl[i] = bitxor(msg_bl[i+1], msg_br[i+1])
			msg_bl[i] = bitxor(msg_bl[i], keykey[i])
			if i % 2 == 1:
				msg_bl[i] = bitxor(msg_bl[i], '1' * 64)
			msg_br[i] = msg_bl[i+1]
		for i in range(0, 64, 8):
			tt = int(msg_bl[0][i:i+8], 2)
			if tt < 32 or tt >= 127:
				return
			msg += chr(tt)
		for i in range(0, 64, 8):
			tt = int(msg_br[0][i:i+8], 2)
			if tt < 32 or tt >= 127:
				return
			msg += chr(tt)
		

	if "ASIS{" in msg:
		print(msg)


def work(idx, p, r):
	if idx == 8:
		true_work(p, r)
	for i in range(0, 8):
		if p[i] == -1:
			p[i] = idx
			work(idx+1, p, r)
			p[i] = -1

for i in tqdm(range(0, 254)):
	p = [-1] * 8
	work(0, p, i)
