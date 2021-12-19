import time
import multiprocessing as mp
from sage.all import *
from tqdm import tqdm

proof.all(False)

ls = list(prime_range(3,117))
p = 4 * prod(ls) - 1
base = bytes((int(p).bit_length() + 7) // 8)

print(len(ls))
print(int(p).bit_length())

def montgomery_coefficient(E):
    POL = PolynomialRing(GF(p), 't')
    t = POL.gen()
    a,b = E.short_weierstrass_model().a_invariants()[-2:]
    r, = (t**3 + a*t + b).roots(multiplicities=False)
    s = sqrt(3*r**2 + a)
    return -3 * (-1)**is_square(s) * r / s

def csidh(pub, priv):
    assert type(pub) == bytes and len(pub) == len(base)
    E = EllipticCurve(GF(p), [0, int.from_bytes(pub,'big'), 0, 1, 0])
    assert (p+1) * E.random_point() == E(0)
    for es in ([max(0,+e) for e in priv], [max(0,-e) for e in priv]):
        while any(es):
            x = GF(p).random_element()
            try: P = E.lift_x(x)
            except ValueError: continue
            k = prod(l for l,e in zip(ls,es) if e)
            P *= (p+1) // k
            for i,(l,e) in enumerate(zip(ls,es)):
                if not e: continue
                k //= l
                phi = E.isogeny(k*P)
                E,P = phi.codomain(), phi(P)
                es[i] -= 1
        E = E.quadratic_twist()
    return int(montgomery_coefficient(E)).to_bytes(len(base),'big')
    
def csidh_verbose(pub, priv):
    assert type(pub) == bytes and len(pub) == len(base)
    E = EllipticCurve(GF(p), [0, int.from_bytes(pub,'big'), 0, 1, 0])
    assert (p+1) * E.random_point() == E(0)
    cnts = [0 for _ in ls]
    ok = False
    for es in ([max(0,+e) for e in priv], [max(0,-e) for e in priv]):
        while any(es):
            x = GF(p).random_element()
            try: P = E.lift_x(x)
            except ValueError: continue
            k = prod(l for l,e in zip(ls,es) if e)
            P *= (p+1) // k
            for i,(l,e) in enumerate(zip(ls,es)):
                if not e: continue
                k //= l
                if k * P != E(0):
                    if ok:
                        cnts[i] -= 1
                    else:
                        cnts[i] += 1
                phi = E.isogeny(k*P)
                E,P = phi.codomain(), phi(P)
                es[i] -= 1
        E = E.quadratic_twist()
        ok = True
    return int(montgomery_coefficient(E)).to_bytes(len(base),'big'), cnts

def csidh_correct(pub, priv):
    assert type(pub) == bytes and len(pub) == len(base)
    E = EllipticCurve(GF(p), [0, int.from_bytes(pub,'big'), 0, 1, 0])
    assert (p+1) * E.random_point() == E(0)
    for es in ([max(0,+e) for e in priv], [max(0,-e) for e in priv]):
        while any(es):
            x = GF(p).random_element()
            try: P = E.lift_x(x)
            except ValueError: continue
            k = prod(l for l,e in zip(ls,es) if e)
            P *= (p+1) // k
            for i,(l,e) in enumerate(zip(ls,es)):
                if not e: continue
                Q = (k // l) * P
                if Q != E(0):
                    phi = E.isogeny(Q)
                    E,P = phi.codomain(), phi(P)
                    es[i] -= 1
                k = k // l
        E = E.quadratic_twist()
    return int(montgomery_coefficient(E)).to_bytes(len(base),'big')

def apply_l_isogeny(E, l):
    while True:
        x = GF(p).random_element()
        try:
            P = E.lift_x(x)
        except ValueError: continue
        P = P * ((p+1)//l)
        if P == E(0): continue
        phi = E.isogeny(P)
        E = phi.codomain()
        return E

def apply_inv_l_isogeny(E, l):
    Et = E.quadratic_twist()
    Et = apply_l_isogeny(Et, l)
    return Et.quadratic_twist()
    
def my_csidh_correct(pub, priv):
    assert type(pub) == bytes and len(pub) == len(base)
    E = EllipticCurve(GF(p), [0, int.from_bytes(pub,'big'), 0, 1, 0])
    for i in range(29):
        if priv[i] < 0:
            for j in range(abs(priv[i])):
                E = apply_inv_l_isogeny(E, ls[i])
        if priv[i] > 0:
            for j in range(priv[i]):
                E = apply_l_isogeny(E, ls[i])
    return int(montgomery_coefficient(E)).to_bytes(len(base),'big')
    

print("building query bases")

REMOTE = False


queries = # precomputed queries
if REMOTE == False:
    priv = [randrange(-2, 3) for _ in ls]
    print(priv)

results = [0] * 500
mark1 = [0] * 29
mark2 = [0] * 29
fre = 0
cc = 0

print("building results")

act_counts = [[0] * 29 for _ in range(500)]
st = time.time()
for i in tqdm(range(500)):
    if REMOTE == False:
        results[i], cnts = csidh_verbose(bytes.fromhex(queries[i][2]), priv)
        res = 0
        for j in range(29):
            if cnts[j] != priv[j]:
                res += abs(cnts[j] - priv[j])
        if res == 0:
            fre += 1
        if res <= 2:
            cc += 1
        for j in range(29):
            if cnts[j] != priv[j]:
                if res == 1: 
                    mark1[j] = 1
                    mark2[j] = 1
                if res == 2:
                    mark2[j] = 1
    for j in range(29):
        act_counts[i][j] = cnts[j]
    if queries[i][0] == -1 and queries[i][1] == -1:
        continue 
    app_inv = [0] * 29
    app_inv[queries[i][0]] = -1
    app_inv[queries[i][1]] = 1
    results[i] = csidh_correct(results[i], app_inv)
    
    assert results[i] == csidh_correct(base, cnts)

if REMOTE == False:
    for j in range(29):
        if priv[j] == 0:
            mark1[j] = 1
            mark2[j] = 1
    print(fre)
    print(cc)
    print(mark1)
    print(mark2)

en = time.time()

print(en - st)

print("building dicts")

st = time.time()
dicts = [dict() for _ in range(500)]

def calc_dic(args):
    res, idx = args 
    ret = dict()
    ret[res] = 0
    for j in range(29):
        app = [0] * 29
        app[j] = 1
        cc = csidh_correct(res, app)
        ret[cc] = j+1
    for j in range(29):
        app = [0] * 29
        app[j] = -1
        cc = csidh_correct(res, app)
        ret[cc] = -(j+1)
    return [idx, ret]


for i in tqdm(range(0, 500, 10)):
    pool = mp.Pool(10)
    params = [(results[j], j) for j in range(i, i+10)]
    solutions = list(pool.map(calc_dic, params))
    for j in range(10):
        dicts[solutions[j][0]] = solutions[j][1]

en = time.time()

print(en - st)

print("building diffs")

st = time.time()

def calc_dif(u, v):
    A = set(dicts[u].keys())
    B = set(dicts[v].keys())
    C = list(A.intersection(B))
    if len(C) == 0:
        return None 
    x = dicts[u][C[0]]
    y = dicts[v][C[0]]
    ret = [0] * 29
    # u + x = v + y
    # v = u + x - y
    if x >= 1:
        ret[x-1] += 1
    if x <= -1:
        ret[-x-1] -= 1
    if y >= 1:
        ret[y-1] -= 1
    if y <= -1:
        ret[-y-1] += 1
    return ret 
    
    
res = [[0] * 29 for _ in range(500)]
vis = [0] * 500
queue = []

queue.append(0)
vis[0] = 1

while len(queue) > 0:
    x = queue[0]
    queue = queue[1:]
    for i in range(500):
        if vis[i] == 1:
            continue
        dif = calc_dif(x, i)
        if dif == None:
            continue 
        for j in range(29):
            res[i][j] = res[x][j] + dif[j]
        queue.append(i)
        vis[i] = 1

print(sum(vis))
for i in range(500):
    if vis[i] == 0:
        continue
    for j in range(29):
        assert res[i][j] == act_counts[i][j] - act_counts[0][j]
        
en = time.time()
print(en - st)

print("finalizing signs")

st = time.time()

dirc = [0] * 29
for i in range(29):
    vv = [0] * 7
    for j in range(500):
        if vis[j] == 1:
            vv[res[j][i] + 3] += 1
    print(vv)
    mx = 0
    idx = -1
    for j in range(7):
        if vv[j] > mx:
            mx = vv[j]
            idx = j
    bel = 0
    for j in range(idx):
        bel += vv[j]
    abv = 0
    for j in range(idx+1, 7):
        abv += vv[j]
    if bel == abv and bel == 0:
        dirc[i] = 0
    elif bel > abv:
        dirc[i] = 1
    else:
        dirc[i] = -1

en = time.time()
print(en - st)

print(dirc)
if REMOTE == False:
    print(priv)
    
    
    
        
