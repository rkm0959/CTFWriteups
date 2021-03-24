def Jacobi(a, n): # Jacobi Symbol (a/n)
	if n % 2 == 0:
		raise ValueError
	if a == 1:
		return 1
	if a == n - 1:
		if n % 4 == 1:
			return 1
		else:
			return -1
	v_2 = 0 # number of 2s that a has
	while a % 2 == 0:
		a //= 2
		v_2 = v_2 + 1
	mul = 1 # multiplied value because of the 2's
	if v_2 % 2 == 1 and (n % 8 == 3 or n % 8 == 5):
		mul = -1
	# now we need to calculate (a/n)
	if a == 1:
		return mul
	# use Quadratic Reciprocity
	if a % 4 == 1 or n % 4 == 1:
		return mul * Jacobi(n % a, a)
	else:
		return -1 * mul * Jacobi(n % a, a)

r = remote('crypto2.q21.ctfsecurinets.com', '1337')
s = r.recvline()
print(s)
pfix = s.split()[5][7:]
print(pfix)
cnt = 0
while True:
    cnt += 1
    if cnt % 100000 == 0:
        print(cnt // 100000)
    tt = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for i in range(16))
    val = hashlib.sha256(pfix + tt.encode()).hexdigest()
    if val[:6] == '000000':
        r.sendline(tt)
        break 


def get_single(idx):
    s = r.recvline()
    s = s.strip()
    s = s.split()[-idx]
    return int(s.decode())


print(r.recvline())
print(r.recvline())
while True:
    wallet = get_single(2)
    r.recvline()
    print(wallet)
    if wallet > 133337:
        print(r.recv(1024))
        break 
    else:
        n = get_single(1)
        r.recvline()
        if n % 8 == 1 or n % 8 == 7:
            r.sendline(str(1))
        else:
            r.sendline(str(wallet))
        choice = get_single(1)
        r.recvline()
        if Jacobi(choice, n) == 1:
            r.sendline("0")
        else:
            r.sendline("1")
        r.recvline()