r = remote('crypto.ctf.zer0pts.com', '10463')
r.recvline()
 
s = r.recvline()
T = s.split()
g = int(T[4][:-1])
p = int(T[-1].rstrip())
 
 
QR = []
NQR = []
 
if pow(g, (p-1)//2 , p) != 1:
    print("BAD PRIME 1")
    exit()
QR.append(1)
if pow(2, (p-1)//2, p-1) == 1:
    QR.append(2)
else:
    NQR.append(2)
if pow(3, (p-1)//2, p-1) == 1:
    QR.append(3)
else:
    NQR.append(3)
 
if len(QR) == 3:
    print("lol")
    exit()
 
def get_commit():
    s = r.recvline()
    t = s.split(b'(')[-1]
    c1 = int(t.split(b',')[0])
    c2 = int(t.split(b',')[1][1:-2])
    return c1, c2
 
for i in range(0, 500):
    print(r.recvline())
    c1, c2 = get_commit()
    if pow(c2, (p-1) // 2, p) == 1:
        if len(QR) == 1:
            r.sendline(b"3")
        else:
            if 2 in QR:
                r.sendline(b"1")
            else:
                r.sendline(b"3")
    else:
        if len(NQR) == 1:
            if 2 in NQR:
                r.sendline(b"1")
            if 3 in NQR:
                r.sendline(b"2")
        else:
            r.sendline(b"2")
    r.recvline()
    r.recvline()
    r.recvline()
    s = r.recvline()
    if s.split()[-1].rstrip() == b"draw!!!":
        continue
    else:
        s = r.recvline()
        print(s)
        if s.split()[-1].rstrip() == b"100":
            for t in range(0, 4):
                print(r.recvline())