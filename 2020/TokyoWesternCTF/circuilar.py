def comb(x1, y1, x2, y2, k, n):
    return (x1 * x2 + k * y1 * y2) % n, (x1 * y2 - x2 * y1) % n
 
def solve(k, m, n): ## solve x^2 + ky^2 == m mod n
    print("solve", k, m, n)
    fu = kthp(m, 2)
    if fu * fu == m:
        return (fu, 0)
    if k < 0:
        se = kthp(-k, 2)
        if se * se == -k:
            retx = (m+1) * inverse(2, n) % n 
            rety = (m-1) * inverse(2 * se, n) % n
            return retx, rety
    if m == 1:
        return (1, 0)
    if m == k % n:
        return (0, 1)
    while True:
        u = random.getrandbits(1024)
        v = random.getrandbits(1024)
        m_0 = (m * (u * u + k * v * v)) % n
        if isPrime(m_0):
            if GCD(m_0, n) != 1:
                print("LOL", m_0)
                exit()
            x_0 = tonelli(m_0, (-k) % m_0)
            if (x_0 * x_0 + k) % m_0 == 0:
                break
    ms = [m_0]
    xs = [x_0]
    sz = 1
    while True:
        new_m = (xs[sz-1] * xs[sz-1] + k) // ms[sz-1]
        ms.append(new_m)
        if k > 0 and xs[sz-1] <= ms[sz] <= ms[sz-1]:
            sz = sz + 1
            break
        if k < 0 and abs(ms[sz]) <= kthp(abs(k), 2):
            sz = sz + 1
            break
        xs.append(min(xs[sz-1] % ms[sz], ms[sz] - (xs[sz-1] % ms[sz])))
        sz = sz + 1
    assert sz == len(ms)
    assert sz - 1 == len(xs)
    uu, vv = xs[0], 1
    dv = 1
    for i in range(1, sz-1):
        assert (xs[i] ** 2 + k) % n == (ms[i] * ms[i+1]) % n
        uu, vv = comb(uu, vv, xs[i], 1, k, n)
        dv = (dv * ms[i]) % n
    dv = (dv * ms[sz-1]) % n
    uu = (uu * inverse(dv, n)) % n 
    vv = (vv * inverse(dv, n)) % n
    X, Y = solve(-ms[sz-1], (-k) % n, n)
    soly = inverse(Y, n)
    solx = (X * soly) % n
    finx, finy = comb(solx, soly, uu, vv, k, n)
    godx = ((finx * u - k * finy * v) * inverse(u * u + k * v * v, n)) % n
    gody = ((finx * v + finy * u) * inverse(u * u + k * v * v, n)) % n
    return godx, gody
 
msg = 'SUNSHINE RHYTHM'
hsh = ''
 
for i in range(0, 4):
    cc = msg + chr(ord('0') + i)
    hsh += hashlib.sha512(cc.encode()).hexdigest()
 
request = {
    'cmd': 'pubkey'
}
X = web_request('POST', 'https://crypto02.chal.ctf.westerns.tokyo', request, False)
 
 
n = 25299128324054183472341067223932160732879350179758036557232544635970111090474692853470743347443422497121006796606102551210094872253782062717537548880909979729182337501587763866901367212812697076494080678616385493076865655574412317879297160790121009524506015912113098690685202868184636344610142590510988192306870694667596904330867479578103616304053889409982447653859514868824002960431331342963562137691362725961627846051021103954795862501700267818317148154520620016172888281127685503677751830350686839873220480306266506898497203511851305686566444690384065880667273398255172752236076702247451872387522388546088290187449
k = 31019613858513746556266176233462864650379070310554671955689986199007361221356361736128815989480106678809272137963430923820800280374078610631771089089882153619351592434728588050285853284795554255483472955286848474793299446184220594124878818081534965835159741218233013815338595300394855159744354636541274026478456851924371621879725248093305782590590080796638483359868136648681381332610536250576568502512250581068814961097404403694071264894656697723213779631364079010490113719021172301802643377777927176399460547584115127172190000090756708138720022664973312744713394243720961199400948876916817452969615149776530401604593 % n
goal = int(hsh, 16) % n 
 
x, y = solve(k, goal, n)
print((x * x + k * y *y - goal) % n)
 
request = {
    'cmd': 'verify',
    'x': str(x),
    'y': str(y),
    'msg': msg
}
 
X = web_request('POST', 'https://crypto02.chal.ctf.westerns.tokyo', request, False)
print(X)
