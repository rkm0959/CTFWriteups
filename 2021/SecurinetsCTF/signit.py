r = remote('crypto2.q21.ctfsecurinets.com', '13337')
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


p = 0x402969301d0ec23afaf7b6e98c8a6aebb286a58f525ec43b46752bfc466bc435
gx = 0x3aedc2917bdb427d67322a1daf1073df709a1e63ece00b01530511dcb1bae0d4
gy = 0x21cabf9609173616f5f50cb83e6a5673e4ea0facdc00d23572e5269632594f1d
a = 0x2ad2f52f18597706566e62f304ae1fa48e4062ee8b7d5627d6f41ed24dd68b97
b = 0x2c173bd8b2197e923097541427dda65c1c41ed5652cba93c86a7d0658070c707
q = 0x402969301d0ec23afaf7b6e98c8a6aeb2f4b05d0bbb538c027395fa703234883


E = EllipticCurve(GF(p), [a, b])
# (x, y) are calculated by lift_x'ing multiples of n / 157
n = 29021189019488943486379030274004990662065999689595887203366412471281037559939
x = 739393350815004929589274656662547532791490437951487572060290763599516880508
y = 20300402999023192908416140705307344972602995444583537510039959615998359333548

proof = 'Give me flag.'

print(r.recvline())
print(r.recvline())
print(r.recvline())
r.sendline(str(x))
r.sendline(str(y))

print(r.recvline())

# r = G.x 
# s = hash + G.x * secret

hsh = int(hashlib.sha256(proof.encode()).hexdigest(), 16)

for i in range(1, 157):
    msg = proof
    rr = x
    s = (hsh + rr * i) % n
    r.sendline(msg)
    r.sendline(str(rr))
    r.sendline(str(s))
    tt = r.recvline()
    if b"Valid" in tt:
        print(r.recv(1024))