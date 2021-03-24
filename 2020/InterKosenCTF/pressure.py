HOST = "misc.kosenctf.com"
PORT = 10002

conn = pwnlib.tubes.remote.remote(HOST, PORT)

solution = "KosenCTF{"
chars = [chr(x) for x in range(32, 128)]
dumb = ';'

while True:
	p = (solution + dumb) * 5
	r = conn.send(str.encode(p + "\n"))
	res = conn.recvline()
	res = res[22:-1]
	res = base64.b64decode(res)
	res = len(res)
	## print(res)
	for c in chars:
		ntry = (solution + c) * 5
		r = conn.send(str.encode(ntry + "\n"))
		r = conn.recvline()
		r = r[22:-1]
		r = base64.b64decode(r)
		r = len(r)
		## print(r)
		if r < res:
			res = r
			solution += c
			print(solution)
			if c == "}":
				print("Solution Found!", solution)
				exit()
			break