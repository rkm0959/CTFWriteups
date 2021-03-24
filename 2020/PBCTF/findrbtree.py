prop_list = ["Eyewear", "Eye color", "Hair", "Outerwear", "T-shirt color", "Trousers", "Socks color", "Shoes"]
prop = {
    "Eyewear": ["Glasses", "Monocle", "None"],
    "Eye color": ["Brown", "Blue", "Hazel"],
    "Hair": ["Straight", "Curly", "Bald"],
    "Outerwear": ["Coat", "Hoodie", "Poncho"],
    "T-shirt color": ["Red", "Orange", "Green"],
    "Trousers": ["Jeans", "Leggings", "Sweatpants"],
    "Socks color": ["Black", "Gray", "White"],
    "Shoes": ["Boots", "Slippers", "Sneakers"],
}
 
def checker(i, j, desc):
    for t in range(0, 3):
        if (1 << t) & j and desc[i] == prop[prop_list[i]][t]:
            return True
    return False
 
def ask_query(whi_i, whi_j):
    r.sendline(prop_list[whi_i])
    s = ""
    for i in range(0, 3):
        if whi_j & (1 << i):
            s += prop[prop_list[whi_i]][i]
            s += " "
    s = s[:-1]
    r.sendline(s)
    res = r.recvline()
    print(res)
    sx = False
    if b"YES" in res:
        sx = True
    return sx
 
def gogo(ppl_desc, num_query):
    print(len(ppl_desc))
    if len(ppl_desc) == 1:
        if num_query >= 1:
            r.sendline(b"Solution")
        s = ""
        for i in range(0, 8):
            s += ppl_desc[0][i]
            if i != 7:
                s += " "
        r.sendline(s)
        r.recvline()
        return
    if num_query == 0:
        t = random.randrange(0, len(ppl_desc))
        s = ""
        for i in range(0, 8):
            s += ppl_desc[t][i]
            if i != 7:
                s += " "
        r.sendline(s)
        r.recvline()
        return
    T = len(ppl_desc)
    whi_i, whi_j, opt = -1, -1, 0
    for i in range(0, 8):
        for j in range(1, 4):
            cnt = 0
            for k in range(0, T):
                ex = checker(i, j, ppl_desc[k])
                if ex == True:
                    cnt += 1
            if min(cnt, T-cnt) > opt:
                opt = min(cnt, T-cnt)
                whi_i, whi_j = i, j
    sx = ask_query(whi_i, whi_j)
    nppl_desc = []
    for k in range(0, T):
        ex = checker(whi_i, whi_j, ppl_desc[k])
        if ex == sx:
            nppl_desc.append(ppl_desc[k])
    gogo(nppl_desc, num_query - 1)
    return
 
def solve(num_pp, num_ask):
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    ppl_desc = []
    for i in range(0, num_pp):
        cur = []
        r.recvline()
        for j in range(0, 8):
            s = r.recvline()
            s = s.split(b":")[1]
            s = s[1:-1].decode()
            cur.append(s)
        ppl_desc.append(cur)
        r.recvline()
    r.recvline()
    gogo(ppl_desc, num_ask)
 
 
r = remote("find-rbtree.chal.perfect.blue", 1)
 
for i in range(0, 9):
    r.recvline()
 
cases = [(5, 3), (7, 3), (10, 4), (15, 4), (20, 5), (25, 5), (50, 6), (75, 7), (100, 8), (250, 9)]
cases += [(400, 10)] * 5 + [(750, 11)] * 5 + [(1000, 12)] * 5 + [(1600, 12)] * 5
 
for i in range(0, 30):
    solve(cases[i][0], cases[i][1])
 
print(r.recvline())
