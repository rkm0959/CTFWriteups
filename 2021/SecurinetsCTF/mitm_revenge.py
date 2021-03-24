r = remote('crypto1.q21.ctfsecurinets.com', '13337')

g = 2
p = 0xf18d09115c60ea0e71137b1b35810d0c774f98faae5abcfa98d2e2924715278da4f2738fc5e3d077546373484585288f0637796f52b7584f9158e0f86557b320fe71558251c852e0992eb42028b9117adffa461d25c8ce5b949957abd2a217a011e2986f93e1aadb8c31e8fa787d2710683676f8be5eca76b1badba33f601f45
h = pow(g, (p-1)//2, p)

def get_single():
    s = r.recvline()
    s = s.strip()
    s = s.split()[-1]
    return int(s.decode())

def get_double():
    s = r.recvline()
    s = s.strip()
    A = s.split()[-2][1:-1]
    B = s.split()[-1][:-1]
    return int(A.decode()), int(B.decode())

ga = get_single()
gab, bnonce = get_double()
gb = get_single()

r.sendline(str(gab))

gabc, cnonce = get_double()

val = gabc ^ bnonce 

r.sendline(str(h) + " " + str(h ^ val))

gc = get_single()
r.sendline(str(123))
shit1 = get_single()

r.sendline(str(h) + " " + str(h ^ val))

print(val)
print(r.recvline())
print(r.recvline())
print(r.recvline())