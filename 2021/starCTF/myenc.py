r = remote('52.163.228.53', 8081)

def getres(header):
	t = r.recvline()
	t = t[len(header) + 1 : ]
	if t[-1] == b'\n':
		t = t[:-1]
	return int(t.decode())

S = r.recvline()
S = S.split(b' == ')
print(S[0], S[1])
X = S[0][-17:-1].decode()
print(X)
Y = S[1][:-1].decode()
print(Y)
r.recvline()

while True:
	rand = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(0, 4))
	if sha256((rand + X).encode()).hexdigest() == Y:
		print(rand)
		r.sendline(rand)
		break


n = getres("n:")

res = "00101010010000"

print(r.recvline())
r.sendline(b"0")
val_0 = getres("done:")

print(r.recvline())
r.sendline(b"1")
val_1 = getres("done:")

# val_0 == iv (mod q)
# val_1 == iv - 1 (mod q)

q = GCD(val_1 + 1 - val_0, n)
iv = (val_1 + 1) % q

p = n // q

phi = (p-1) * (q-1)

print(n, p, q)

def calc(v, c):
	ex = pow(c, c ** c, phi)
	return pow(v, ex, n)
	
m = 356
strs = []
vals = []

for i in range(0, 128):
	tot = iv
	sss = ""
	for j in range(0, 7):
		if (i & (1 << j)) == (1 << j):
			sss += "1"
			tot += calc(m^q, j+1)
		else:
			sss += "0"
	strs.append(sss)
	vals.append(tot % q)

for i in range(0, 20):
	print(r.recvline())
	r.sendline(b"356")
	val = getres("done:")
	val = val % q
	for j in range(0, 128):
		if val == vals[j]:
			res += strs[j]
			break

flag = ""
for i in range(0, 15):
	vv = int(res[8*i:8*i+8], 2)
	flag += chr(vv)

print(flag)