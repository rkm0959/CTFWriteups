HOST = "crypto.kosenctf.com"
PORT = 13005

# server
conn = pwnlib.tubes.remote.remote(HOST, PORT)
print(conn.recvline())
conn.send("ffffffffffffffffffff\n")
print(conn.recvline())

# sage part
## (98664527284046924431103876265370791373438293020179316375883642857046660842422 : 51449822108608164116773906593599196539335313713052966364410874461652593273305 : 1)


# read values
msg = binascii.unhexlify("ffffffffffffffffffff")
r = 98909165505886332260977490746820914928283581853841477470132641900339514121815
s = 86962637426480431206806090924202825437488410614468755585865520420765819501712

z = bytes_to_long(msg)
kt = int(sha1(msg).hexdigest(), 16)
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

## s = (z + r * pvk) / (kt * pvk)
## s * kt * pvk == z + r * pvk

pvk = z * inverse(s * kt - r, n) % n

print(pvk)
print(bytes_to_long(b'ochazuke'))

# connect server again
fr = 98165594340872803797719590291390519389514915039788511532783877037454671871717
fs = 115665584943357876566217145953115265124053121527908701836053048195862894185539

mys = "(" + str(fr)  + ", " + str(fs) + ")"
conn.send(mys + "\n")
print(conn.recvline())
