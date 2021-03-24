def gf2(src1, src2):
    ret = 0
    for i in range(0, 8):
        if (src2 & (1 << i)) > 0:
            ret = ret ^ (src1 << i)
    for i in range(14, 7, -1):
        p = 0x11B << (i - 8)
        if (ret & (1 << i)) > 0:
            ret = ret ^ p
    assert 0 <= ret < 256
    return ret
 
f = open("ciphertext", "rb")
f = f.read()
 
L = len(f)
print(L)
 
cc = []
for i in range(12, 13): # should brute over 1 ~ 16
    for j in range(0, i):
        cmx, whi = 0, 0
        for k in range(1, 256):
            cnt = 0
            for l in range(j, L, i):
                t = gf2(k, f[l]) 
                if 32 <= t <= 128:
                    cnt += 1
            if cmx < cnt:
                cmx = cnt
                whi = k
        cc.append(whi)
 
res = b""
 
for i in range(0, L):
    res += long_to_bytes(gf2(cc[i % 12], f[i]))
 
print(res)