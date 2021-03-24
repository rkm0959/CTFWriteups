def connect():
    r = remote('queensarah2.chal.perfect.blue', 1)
    return r
 
def get_index(t):
    if ord('a') <= ord(t) <= ord('z'):
        return ord(t) - ord('a')
    return 26 
 
def attempt():
    dcyc = [0] * (27 * 27)
    AL = ascii_lowercase + "_"
    r = connect()
    r.recvline()
    true_val = r.recvline()[2:-3].decode()
    for i in range(0, 27):
        for j in range(0, 27):
            s = AL[i] + AL[j]
            print(s)
            r.sendline(s)
            r.recvline()
            res = r.recvline()[0:2].decode()
            idx = 27 * get_index(res[0]) + get_index(res[1])
            dcyc[27 * i + j] = idx # square of permutation
    vis = [0] * (27 * 27 + 5)
    sz = [0] * (27 * 27 + 5)
    fk = [0] * (27 * 27 + 5)
    # get cycles of the square permutation 
    for i in range(0, 27 * 27):
        if vis[i] == 1:
            continue
        cur, t = i, 0
        L = []
        while vis[cur] == 0:
            L.append(cur)
            t += 1
            vis[cur] = 1
            cur = dcyc[cur]
        if sz[t] >= 1 or t % 2 == 0: # all cycle's length different
            return
        sz[t] += 1
        for x in L:
            fk[x] = t
    # compute original permutation
    cyc = [0] * (27 * 27)
    for i in range(0, 27 * 27):
        it = (fk[i] + 1) // 2
        u = i
        for j in range(0, it):
            u = dcyc[u]
        cyc[i] = u
    invcyc = [0] * (27 * 27)
    for i in range(0, 27 * 27):
        invcyc[cyc[i]] = i
    # decryption process
    rounds = int(2 * math.ceil(math.log(len(true_val), 2)))
    for i in range(0, rounds):
        if i != 0:
            msg = ''
            for j in range(0, len(true_val) // 2):
                msg = msg + true_val[j]
                msg = msg + true_val[j + len(true_val) // 2]
            true_val = msg
        msg = ''
        for j in range(0, len(true_val), 2):
            cc = 27 * get_index(true_val[j]) + get_index(true_val[j+1])
            cc = invcyc[cc]
            u = cc // 27
            v = cc % 27
            msg += AL[u]
            msg += AL[v]
        true_val = msg
    print(true_val)
    r.sendline(true_val)
    print(r.recvline())
 
NUM_ATTEMPT = 1000
for i in range(0, NUM_ATTEMPT):
    print("[+] Attempt ", i)
    attempt()
