HOST = "crypto.kosenctf.com"
PORT = 13003

conn = pwnlib.tubes.remote.remote(HOST, PORT)
conn.send("@\n")
print(conn.recvline())
print(bytes_to_long("yoshiking, give me ur flag".encode()))

z = 195139091440424100361889710829481093024970143303085039083610471
c = bin(z)[2:]
c = str(c)

q = 2

res = ""
print(c)
for t in c:
	if t == '0':
		q += 1
		res += str(q*q) + ","
	if t == '1':
		q += 1
		res += str(2*q*q) + ","

res = res[:-1]
print(res)
conn.send(res + "\n")

print(conn.recvline())
print(conn.recvline())