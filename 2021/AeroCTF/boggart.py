# reading parameters
def recvint():
    T = r.recvline()
    return int(T[:-1].decode(), 10)
 
 
def get_vals():
    r.recvline()
    C = recvint()
    N = recvint()
    H = bytes_to_long(b'the boy who lived')
    H_AFTER = recvint()
    F_AFTER = recvint()
    return C, N, H_AFTER, F_AFTER

# factorization
def bsum(x):
    ret = 0
    while x > 0:
        ret += x % 2
        x //= 2
    return ret 
 
def factor(N, C, cand, k):
    if len(cand) == 0:
        return
    print(k, len(cand))
    # fix pq mod 2^{k+1} by adding 2^k or not
    ret = []
    if (C >> k) % 2 == 1: # we know p, q has 2^k
        for p, q in cand:
            if p * q == N:
                print(p)
                print(q)
                return
            pp = p + (1 << k)
            qq = q + (1 << k)
            if (pp * qq - N) % (1 << (k + 1)) == 0 and pp * qq <= N:
                ret.append((pp, qq))
        factor(N, C, ret, k + 1)
    else:
        for p, q in cand:
            if p * q == N:
                print(p)
                print(q)
                return
            for i in range(0, 2):
                for j in range(0, 2):
                    pp = p + i * (1 << k)
                    qq = q + j * (1 << k)
                    if (pp * qq - N) % (1 << (k + 1)) == 0 and pp * qq <= N:
                        ret.append((pp, qq))
        factor(N, C, ret, k + 1)
 
# encryption
def mlucas(v, a, n): # encryption fast, from Wikipedia
    v1, v2 = v, (v**2 - 2) % n
    for bit in bin(a)[3:]:
        if bit == "0":
            v1, v2 = ((v1**2 - 2) % n, (v1*v2 - v) % n)
        else:
            v1, v2 = ((v1*v2 - v) % n, (v2**2 - 2) % n)
    return v1
 
def REV(val, ex, pr): # decryption modulo a prime
    # t^n + 1/t^n = val
    if val == 0: # if invalid
        return 0 # return invalid
    cc = tonelli((val * val - 4) % pr, pr) # modular sqrt
    if cc == -1: # failure
        return 0 # return failure
    tn = ((val + cc) * inverse(2, pr)) % pr
    t = pow(tn, inverse(ex, pr-1), pr)
    return ((t + inverse(t, pr))) % pr


H = bytes_to_long(b'the boy who lived')
sys.setrecursionlimit(10 ** 6)
 
C = 12124756848659098434025945489515506912896022954145117746118560512007665385702760439414990812257455576297349156226093149988609289245714223348281989890389750
N = 157597985389833012337654133040126048344064622845161536236706459270343905778002470548499258715513540516431526518690532156245280894778788692043941237295606686168037171464988128988463706375526180496632421973522548093894845498612792150825707672843107252573999144787226703076358545319417530365329436368718460943493
HAFTER = 66161881147822169408519540711422900962287264738494143175834051626001922954586728648835878096124744364195826536091510407493007528877139856387261499433277826944946254511824024047480941829026088269865298686453128715170657018128276813244425143986311708022950785583195028647859774987948632731985531259912781472862
FAFTER = 149186530719822614329126547638374064715014252925601014676661223009475822460330945440469384214084001910035138025738722725987466200681944900264994344927428683388976167111544750466576538413516454786176229441173029050647235653998791477157269246962955063391947778663841551982999293815571149539542758304215156142104
 
C -=  C % (1 << 16)
C &= (C + (1 << 16))
 
factor(N, C, [(1, 1)], 1) # this finds p, q
 
p = 12558711464274427739528720572494472142909592647353129013838950445222814801805965383430302364628487022743397586481672449715551542652546057434522020868473011
q = 12548897698474048380978452887676419841595083766206501465313606366388795637681128899285066184154566275021196792336453455837893284460576050862858626214885863

# begin meet in the middle
primes = [31337, 31357, 31379, 31387, 31391, 31393, 31397, 31469, 31477, 31481, 31489, 31511, 31513, 31517, 31531, 31541, 31543, 31547, 31567, 31573, 31583, 31601, 31607, 31627, 31643, 31649, 31657, 31663, 31667, 31687, 31699, 31721, 31723, 31727, 31729, 31741, 31751, 31769, 31771, 31793]
 
L = primes[15:35]
R = primes[:15]
 
LV = []
RV = []
 
# generally, encryption is faster than decryption
# therefore, we leave the "heavy" work for the encryption part...
 
for combo_L in tqdm(itertools.combinations(L, 8)):
    CC = list(combo_L)
    cur = H
    # you can also just multiply all primes and encrypt at once
    for pr in combo_L:
        cur = mlucas(cur, pr, p)
    CC.append(cur)
    LV.append(CC)
 
print("LEFT DONE")
 
for combo_R in tqdm(itertools.combinations(R, 8)):
    CC = list(combo_R)
    cur = HAFTER
    # you can also just multiply all primes and decrypt at once
    for pr in combo_R:
        cur = REV(cur, pr, p)
    CC.append(cur)
    RV.append(CC)
 
print("RIGHT DONE")
 
for i in tqdm(range(len(LV))):
    for j in range(len(RV)):
        if LV[i][8] == RV[j][8]:
            print("FOUND!!")
            print(LV[i])
            print(RV[j])


# recovered set of primes
pr = [31543, 31567, 31573, 31607, 31649, 31667, 31687, 31699, 31357, 31379, 31397, 31469, 31477, 31513, 31517, 31531]
hp = FAFTER % p 
hq = FAFTER % q 
 
# reverse
for i in pr:
    hp = REV(hp, i, p)
    hq = REV(hq, i, q)
 
flag, tt = CRT(hp, p, hq, q) # CRT
print(long_to_bytes(flag))
