r = [0] * 20
s = [0] * 20
k = [0] * 20
h = [0] * 20
 
f = open('output.txt', 'r')
for i in range(0, 20):
    v = f.readline()
    cc = v.split()
    r[i] = int(cc[0][2:], 16)
    s[i] = int(cc[1][2:], 16)
    k[i] = int(cc[2][2:], 16)
    h[i] = int(cc[3][2:], 16) 
 
n = 0x0100000000000000000001F4C8F927AED3CA752257
 
s1 = set()
s2 = set()
 
for i in range(0, 1 << 16):
    # sk = h + r * pvk mod n 
    cc = ((s[0] * (k[0] + i) - h[0]) * inverse(r[0], n)) % n
    s1.add(cc)
 
for i in range(0, 1 << 16):
    cc = ((s[1] * (k[1] + i) - h[1]) * inverse(r[1], n)) % n
    s2.add(cc)
 
print(s1 & s2) # hex this