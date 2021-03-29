from tqdm import tqdm
from sage.all import *

# get values with Arnault's Algorithm

def get_k(x, k):
    return (x & (1 << k)) >> k 

# Arnault 2004.
def check_ok(recovered_bits, lam):
    k = 2 * lam + 1
    r_0, u_0, v_0 = (1 << k), 1, 0 
    val = 0
    for i in range(0, k):
        val += recovered_bits[i] * (1 << i)
    r_1, u_1, v_1 = val, 0, 1
    while r_1 * r_1 > (1 << k):
        s = r_0 // r_1
        t = r_0 % r_1
        u_2, v_2 = u_0 - s * u_1, v_0 - s * v_1
        r_0, u_0, v_0 = r_1, u_1, v_1
        r_1, u_1, v_1 = t, u_2, v_2 
    if max(abs(r_1), abs(v_1)) <= (1 << lam) and v_1 % 2 == 1:
        return r_1, v_1, True
    else:
        return -1, -1, False

com = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00'

f = open('encrypted_png', 'rb')
X = f.read()
f.close()

recovered_bits = []

for i in range(0, len(com)):
    xored = com[i] ^ X[i]
    for j in range(7, -1, -1):
        recovered_bits.append(get_k(xored, j))

print(recovered_bits)

for i in range(10, 72):
    p, q, ok = check_ok(recovered_bits, i)
    if ok == True:
        print(p, q) # 206, -59
        exit()

# now start here
R = Zp(2, prec = 100000)
z = R(206) / R(-59)

fin_bits = []

for i in tqdm(range(0, len(X) * 8)):
    fin_bits.append((int(z.residue(i + 1)) - int(z.residue(i))) // (1 << i))

# sanity check
for i in range(0, len(recovered_bits)):
    assert fin_bits[i] == recovered_bits[i]

FIN = b''
for i in range(0, len(X) * 8, 8):
    val = 0
    for j in range(0, 8):
        val = 2 * val + fin_bits[i + j]
    FIN += bytes([X[i // 8] ^ val])

f = open('fin.png', 'wb')
f.write(FIN)
f.close()


'''
# check header
f1 = open('29072.png', 'rb')
f2 = open('asdf.png', 'rb')
f3 = open('gg.png', 'rb')

X = f1.read()
Y = f2.read()
Z = f3.read()

f1.close()
f2.close()
f3.close()

s = b''

for i in range(0, 300):
    if X[i] == Y[i] == Z[i]:
        s += bytes([X[i]])
    else:
        break 

print(s)
'''