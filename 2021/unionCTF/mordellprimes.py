E = EllipticCurve(QQ,[0,1,0,78,-16])
P = E(1,8)
 
for i in range(2, 40):
    Q = i * P
    cc = Q[0].numerator()
    if N % cc == 0:
        print(cc) # p, q
 
p = cc
q = N / cc
e = 65537
phi = (p-1) * (q-1)
d = inverse(e, phi)
print(long_to_bytes(pow(c, d, N)))