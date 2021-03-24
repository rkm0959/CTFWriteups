def kthp(n, k):
	lef = 1
	rig = 2 ** 400
	while lef <= rig:
		mid = (lef + rig) // 2
		if mid ** k >= n:
			best = mid
			rig = mid - 1
		else:
			lef = mid + 1
	return best

# server connection
HOST = "crypto.kosenctf.com"
PORT = 13001

conn = pwnlib.tubes.remote.remote(HOST, PORT)
print(conn.recvline())

# get data (I was stupid at the time, apparently don't know how to use "for")
conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
conn.send("2\n")
conn.send("3\n")
conn.send("\n")
print(conn.recvline())


conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
conn.send("1\n")
conn.send("4\n")
print(conn.recvline())

conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
conn.send("1\n")
conn.send("5\n")
print(conn.recvline())

conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
conn.send("1\n")
conn.send("6\n")
print(conn.recvline())

conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
conn.send("1\n")
conn.send("7\n")
print(conn.recvline())


# get nonce data
n = 13213917004013074941883923518155352500136040759518468945870343732851737037017858345555718553480688185605981252067134741952110065084206701357744511961587797

rg = 0x0ae26226b16dfc3ca101a1b750f38d0f131fff3c93f04a1222586f

r = kthp(rg, 3)
r = long_to_bytes(r)
r = r[1:]
nonce = 1

print("For c4")
nonce += 1
r = long_to_bytes(((bytes_to_long(r) << 1) ^ nonce) & (2**64 - 1))

print(r[0] | nonce)
print(bytes_to_long(r))

print("For c5")
nonce += 1
r = long_to_bytes(((bytes_to_long(r) << 1) ^ nonce) & (2**64 - 1))

print(r[0] | nonce)
print(bytes_to_long(r))

print("For c6")
nonce += 1
r = long_to_bytes(((bytes_to_long(r) << 1) ^ nonce) & (2**64 - 1))

print(r[0] | nonce)
print(bytes_to_long(r))

print("For c7")
nonce += 1
r = long_to_bytes(((bytes_to_long(r) << 1) ^ nonce) & (2**64 - 1))

print(r[0] | nonce)
print(bytes_to_long(r))
c4 = 0x8043b337fd500f49ff23589ac40d6208d1ba5e8b6af341da6c63d4dc4af8944930cd5812076686450967c0b36a52b66e25a632d9b1780ca0195be15f81c7efe7
c5 = 0x13d464f1f4d139c78e8bbf20eaf9b7693a931e65649db09f259ffc9a17674d72187fb10b10ad3db629c0dcb7048cf9b836972320b0018edae6c0604bf9911a59
c6 = 0x0a7c1297094b925b4dcb42b001c2cfa9b0524939b4bb13048fb8e3778238e28b93c59b010ee2e45c7d7d25da69824a729141caf8c613e6dae1a8c08e153e5ae9
c7 = 0x5ee21f49be33499cce3a157a1ad55d3df5bce4ad99e90f8f91929c2a7a1a8f56a99bf69789137276eaac3294fd4b91fc1ee857eeb3544cd0c4f95be49ab3abd7

res = n - 13213917004013074941883923518155157707200933836201561801562186284370121597148945566062799149031981069879277394219016188339927598569756720133104910406574165

tt = (res * inverse(2 ** 64, n)) % n
print(long_to_bytes(tt))


# sage for GCD
def GCD(f, g, n):
    g = g % f
    if g == 0:
        return f
    t = g.lc()
    if gcd(t, n) != 1:
        print(t)
        exit()
    tt = inverse_mod(Integer(t), n)
    g = g * tt
    return GCD(g, f, n)

n = 13213917004013074941883923518155352500136040759518468945870343732851737037017858345555718553480688185605981252067134741952110065084206701357744511961587797
K = Zmod(n)
P.<x> = PolynomialRing(K, implementation='NTL')
t4 = 179
b4 = 12905559065630283676
t5 = 103
b5 = 7364374057551015739
t6 = 204
b6 = 14728748115102031474
t7 = 157
b7 = 11010752156494511329

c4 = 0x8043b337fd500f49ff23589ac40d6208d1ba5e8b6af341da6c63d4dc4af8944930cd5812076686450967c0b36a52b66e25a632d9b1780ca0195be15f81c7efe7
c5 = 0x13d464f1f4d139c78e8bbf20eaf9b7693a931e65649db09f259ffc9a17674d72187fb10b10ad3db629c0dcb7048cf9b836972320b0018edae6c0604bf9911a59
c6 = 0x0a7c1297094b925b4dcb42b001c2cfa9b0524939b4bb13048fb8e3778238e28b93c59b010ee2e45c7d7d25da69824a729141caf8c613e6dae1a8c08e153e5ae9
c7 = 0x5ee21f49be33499cce3a157a1ad55d3df5bce4ad99e90f8f91929c2a7a1a8f56a99bf69789137276eaac3294fd4b91fc1ee857eeb3544cd0c4f95be49ab3abd7

for i in range(2, 200):
    f4 = (x + 2^(8*i) * t4 + b4)^4 - c4
    f5 = (b5 + x + 2^(8*i) * t5)^5 - c5
    f6 = (b6 + x + 2^(8*i) * t6)^6 - c6
    f7 = (b7 + x + 2^(8*i) * t7)^7 - c7
    f5 = GCD(f4, f5, n)
    f6 = GCD(f5, f6, n)
    f7 = GCD(f6, f7, n)
    if f7.degree() >= 1:
        print(f7)
    
# x + 13213917004013074941883923518155157707200933836201561801562186284370121597148945566062799149031981069879277394219016188339927598569756720133104910406574165
