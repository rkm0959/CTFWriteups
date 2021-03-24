r = remote('crypto.ctf.zer0pts.com', '10130')
 
def recvint():
    s = r.recvline()[:-1]
    s = s.split()[-1]
    return int(s)
 
S = r.recvline()[:-1]
S = S.split()[-1]
V = base64.b64decode(S)
iv = V[:16]
ctxt = V[16:]
 
p = recvint()
keylen = recvint()
 
if p % 4 != 1:
    print("BAD PRIME")
    exit()
 
t = 0
for g in range(2, 2000):
    t = pow(g, (p-1)//4, p)
    if (t * t) % p != 1:
        break
 
print("Begin Key Finding")
keyv = 0
add = 1
for i in tqdm(range(0, 128)):
    t = recvint()
    r.sendline(str(t))
    r.sendline(str((t * t) % p))
    r.sendline(str((t * t * t) % p))
    r.sendline(str(5))
    x = recvint()
    y = recvint()
    z = recvint()
    if pow(x, 4, p) != 1:
        keyv += add
    add = add * 2
    if pow(y, 4, p) != 1:
        keyv += add
    add = add * 2
    if i >= 126:
        keyv = long_to_bytes(keyv)
        aes = AES.new(key=keyv, mode=AES.MODE_CBC, iv=iv)
        ptxt = aes.decrypt(ctxt)
        print(ptxt)
