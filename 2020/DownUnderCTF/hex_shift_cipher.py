def fr(x):
    if 0 <= x and x <= 9:
        return chr(ord('0') + x)
    return chr(ord('a') + x - 10)
 
def cv(x):
    if ord('0') <= ord(x) <= ord('9'):
        return ord(x) - ord('0')
    else:
        return ord(x) - ord('a') + 10
 
def finisher(key, s):
    ct = 'b80e1dd22bc8fcc0034dd809e8f77023fbc83cd02ec8fbb11cc02cdbb62837677bc8f2277eeaaaabb1188bc998087bef3bcf40683cd02eef48f44aaee805b8045453a546815639e6592c173e4994e044a9084ea4000049e1e7e9873fc90ab9e1d4437fc9836aa80423cc2198882a'
    pt = ""
    for i in range(len(ct)):
        ot = cv(ct[i])
        myidx = key.index(ot) ^ s
        m_i = key[myidx]
        pt += fr(m_i)
        s = myidx
    print(bytes.fromhex(pt))
 
def solve(key, s, res, cts, idx):
    if idx == len(res):
        # print("found", key, s)
        finisher(key, s)
        return
    p = cv(res[idx])
    q = cv(cts[idx])
    ## key[index(p) ^ s] == q
    if p in key:
        if key[key.index(p) ^ s] != -1 and key[key.index(p) ^ s] != q:
            return
        it = key.index(p) ^ s
        key[it] = q 
        solve(key, key.index(p), res, cts, idx+1)
        key[it] = -1
    if q in key:
        it = key.index(q) ^ s
        if key[it] != -1 and key[it] != p:
            return
        key[it] = p
        solve(key, key.index(p), res, cts, idx+1)
        key[it] = -1
    for i in range(0, 16):
        if key[i] == -1 and key[i ^ s] == -1:
            key[i] = p
            key[i ^ s] = q
            solve(key, key.index(p), res, cts, idx+1)
            key[i] = -1
            key[i ^ s] = -1
 
res = '54686520736563726574206d6573736167652069733a'
cts = '85677bc8302bb20f3be728f99be0002ee88bc8fdc045'
 
key = [-1] * 16
s = 7
solve(key, s, res, cts, 0)
