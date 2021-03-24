def BIT(v, k):
    cc = bin(v)[2:].zfill(8)
    return ord(cc[k]) - ord('0')
 
invert = []
 
for i in range(0, 8):
    cnt_0, cnt_1 = 0, 0
    for j in range(0, 256):
        if BIT(j, i) == BIT(sbox[j], i):
            cnt_0 += 1
        else:
            cnt_1 += 1
    if cnt_0 > cnt_1:
        invert.append(0)
    else:
        invert.append(1)

def whi(idx, i): # what key bit am I actually using?
    if idx % 2 == 0:
        if i < 32:
            return i
        else:
            return 32 + i
    else:
        if i < 32:
            return 32 + i
        else:
            return 64 + i
 
for i in range(0, 64):
    loc, add = i, 0
    myenc = []
    myenc.append(whi(0, loc)) # key XOR
    for j in range(1, 5):
        add += invert[loc % 8] # sbox
        loc = perm[loc] # pbox
        myenc.append(whi(j % 2, loc)) # key XOR
    myenc.append(add % 2)
    myenc.append(loc)
    arr.append(myenc)
 
r = remote('185.172.165.118', 4004)
pt, ct = [], []
 
print("[+] Receving Plaintext")
 
for i in range(0, 65536):
    tt = r.recvline()
    tt = tt.split(b" ")
    A = bin(int(tt[0][1:-1].decode()))[2:].zfill(64)
    B = bin(int(tt[1][:-2].decode()))[2:].zfill(64)
    pt.append(A)
    ct.append(B)
 
ZERO, ONE = [], []
 
for i in range(0, 64):
    fin = arr[i][-1] # final location
    cnt_0, cnt_1 = 0, 0
    for j in range(0, 65536):
        st = ord(pt[j][i]) - ord('0')
        en = ord(ct[j][fin]) - ord('0')
        if st == (en + arr[i][-2]) % 2: # XOR of the key bits is 0
            cnt_0 += 1
        else: # XOR of the key bits is 1
            cnt_1 += 1
    print(cnt_0, cnt_1) # check bias
    if cnt_0 > cnt_1:
        ZERO.append(arr[i][:-2]) # sum of these = 0
    else:
        ONE.append(arr[i][:-2]) # sum of these = 1

for i in range(0, 8): # ith byte
    print("[+] Guessing key", i)
    ideals = []
    for j in tqdm(range(0, 256)): # bruteforce
        cnt_ideal = 0
        for idx in range(0, 8):
            cnt_0, cnt_1 = 0, 0
            for whi in range(0, 65536): # over ptxt/ctxt pairs
                fin_loc = arr[8 * i + idx][-1]
                addv = arr[8 * i + idx][-2] - invert[idx]
                bt = BIT(sbox[int(pt[whi][8 * i : 8 * i + 8], 2) ^ j], idx) # the first round
                res = ord(ct[whi][fin_loc]) - ord('0')
                if bt == res:
                    cnt_0 += 1
                else:
                    cnt_1 += 1
            cnt_ideal += max(cnt_0, cnt_1) # the correlation
        ideals.append(cnt_ideal)
    mx = 0
    for j in range(0, 256): # max correlation
        mx = max(mx, ideals[j])
    print(ideals.index(mx)) # keys


tt = [49, 53, 49, 49, 57, 56, 102, 100]
ZERO = [[3, 63, 13, 34, 6], [5, 39, 77, 52, 94], [6, 58, 79, 59, 64], [7, 109, 20, 126, 93], [9, 51, 16, 36, 30], [10, 127, 17, 47, 3], [11, 112, 69, 116, 66], [12, 105, 71, 60, 14], [15, 35, 31, 45, 2], [17, 47, 3, 63, 13], [20, 126, 93, 41, 19], [21, 113, 11, 112, 69], [22, 119, 24, 114, 12], [23, 117, 29, 102, 83], [24, 114, 12, 105, 71], [25, 57, 25, 57, 25], [26, 111, 27, 96, 10], [31, 45, 2, 38, 26], [66, 99, 68, 54, 87], [67, 100, 22, 119, 24], [68, 54, 87, 56, 82], [69, 116, 66, 99, 68], [71, 60, 14, 32, 1], [72, 50, 75, 106, 90], [73, 103, 28, 46, 0], [77, 52, 94, 125, 9], [78, 97, 23, 117, 29], [79, 59, 64, 42, 95], [80, 101, 84, 98, 67], [81, 43, 80, 101, 84], [84, 98, 67, 100, 22], [86, 110, 65, 55, 85], [93, 41, 19, 48, 4], [94, 125, 9, 51, 16], [95, 49, 15, 35, 31]]
ONE = [[0, 33, 89, 118, 78], [1, 121, 86, 110, 65], [2, 38, 26, 111, 27], [4, 62, 92, 104, 18], [8, 53, 81, 43, 80], [13, 34, 6, 58, 79], [14, 32, 1, 121, 86], [16, 36, 30, 124, 72], [18, 107, 74, 122, 76], [19, 48, 4, 62, 92], [27, 96, 10, 127, 17], [28, 46, 0, 33, 89], [29, 102, 83, 120, 91], [30, 124, 72, 50, 75], [64, 42, 95, 49, 15], [65, 55, 85, 61, 70], [70, 115, 88, 123, 5], [74, 122, 76, 40, 21], [75, 106, 90, 108, 8], [76, 40, 21, 113, 11], [82, 44, 73, 103, 28], [83, 120, 91, 37, 7], [85, 61, 70, 115, 88], [87, 56, 82, 44, 73], [88, 123, 5, 39, 77], [89, 118, 78, 97, 23], [90, 108, 8, 53, 81], [91, 37, 7, 109, 20], [92, 104, 18, 107, 74]]

cur_row = 0
V = []

M = Matrix(GF(2), 128, 128)
for i in range(0, 128):
    for j in range(0, 128):
        M[i, j] = 0

for i in range(0, 4):
    for j in range(0, 8):
        cc = BIT(tt[i], j)
        M[cur_row, i * 8 + j] = 1
        cur_row += 1
        V.append(cc)

for i in range(0, 4):
    for j in range(0, 8):
        cc = BIT(tt[i + 4], j)
        M[cur_row, i * 8 + j + 64] = 1
        cur_row += 1
        V.append(cc)

for i in range(0, len(ZERO)):
    for j in range(0, len(ZERO[i])):
        M[cur_row, ZERO[i][j]] += 1
    cur_row += 1
    V.append(0)

for i in range(0, len(ONE)):
    for j in range(0, len(ONE[i])):
        M[cur_row, ONE[i][j]] += 1
    cur_row += 1
    V.append(1)

V = vector(GF(2), V)

ttt = M.solve_right(V)
CC = M.right_kernel().basis()
print(len(CC))
ff = []
for i in range(0, 16):
    v = ttt
    for j in range(0, 4):
        if (i & (1 << j)) > 0:
            v += CC[j]
    tt = 0
    print(v)
    for i in range(0, 128):
        tt += (int)(v[i]) * (1 << (127 - i))
    ff.append(tt)
print(ff) # possible keys -> try all