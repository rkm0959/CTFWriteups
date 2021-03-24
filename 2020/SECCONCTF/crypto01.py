def kthp(n, k):
    if n == 0:
        return 0
    lef = 1
    rig = 2
    while rig ** k < n:
        rig = rig << 1
    while lef <= rig:
        mid = (lef + rig) // 2
        if mid ** k <= n:
            best = mid
            lef = mid + 1
        else:
            rig = mid - 1
    return best
 
def ceil(n, m):
    return (n + m - 1) // m
 
def optf(A, M, L, R):
    if L == 0:
        return 0
    if 2 * A > M:
        L, R = R, L
        A = M - A
        L = M - L
        R = M - R
    cc_1 = ceil(L, A)
    if A * cc_1 <= R:
        return cc_1
    cc_2 = optf(A - M % A, A, L % A, R % A)
    return ceil(L + M * cc_2, A)
 
def decrypt(c, d, n):
    n = int(n)
    size = n.bit_length() // 2
 
    c_high, c_low = c
    b = (c_low**2 - c_high**3) % n
    EC = EllipticCurve(Zmod(n), [0, b])
    m_high, m_low = (EC((c_high, c_low)) * d).xy()
    m_high, m_low = int(m_high), int(m_low)
 
    return (m_high << size) | m_low
 
ciphertexts =  []
for C in ciphertexts:
    n = C['n']
    e = C['e']
    c = C['c']
    hint = C['hint']
    CUT = kthp( (int)(n ** 0.2) // 72, 2) * kthp(n, 2) * 8
    x = optf(e, n, 1, CUT)
    R = ((e * x + x - 1) // (n + 2 * kthp(n, 2) + 1))
    L = ((e * x) // (n + 3 * kthp(n//2, 2) + 1))
    y = (L + R) // 2
    assert L == R and x in Primes() and y in Primes()
    sum_L = (x * e) // y - 1 - n
    sum_R = (x * e + x - 1) // y - 1 - n
    lr = (sum_R + kthp(sum_R * sum_R - 4 * n, 2)) // 2
    sm = (sum_L + kthp(sum_L * sum_L - 4 * n, 2)) // 2
    assert sm <= lr
    assert (sm >> 312) == (lr >> 312)
    p_hint = hint
    K = Zmod(n)
    P.<t> = PolynomialRing(K, implementation='NTL')
    f = (p_hint * inverse_mod(2 ** 96, n)) % n + t + (2 ** (312-96)) * (lr >> 312)
    x0 = f.small_roots(X = (2 ** 220), beta = 0.5, epsilon = 0.03)
    ## print(x0)
    p = p_hint + x0[0] * (2 ** 96) + (2 ** 312) * (lr >> 312)
    p = (int)(p)
    q = n // p
    d = inverse_mod(e, (p+1) * (q+1))
    print(decrypt(c, d, n))
 
## thanks, ironore!
def recover_flag(masks, masked_flag):
    flag = reduce(lambda a, b: a ^ b, masks, masked_flag)
    return flag.to_bytes(512 // 8, 'big')


## alternate solution for getting x, y

def get_red(e, n):
    cur_num, cur_den = e, n
    num_1, den_1 = 0, 1
    num_2, den_2 = 1, 0
    while True:
        val = cur_num // cur_den
        nxt_num = cur_den
        nxt_den = cur_num - val * cur_den
        # calculate new convergent
        num_3 = val * num_2 + num_1
        den_3 = val * den_2 + den_1
        if isPrime(num_3) and isPrime(den_3):
            return num_3, den_3
        if den_3 > int(n ** 0.4):
            return -1
        # update convergents
        num_1, den_1 = num_2, den_2
        num_2, den_2 = num_3, den_3
        # update continued fractions
        cur_num, cur_den = nxt_num, nxt_den
 
ciphertexts =  []
for C in ciphertexts:
    n = C['n']
    e = C['e']
    c = C['c']
    hint = C['hint']
    y, x = get_red(e, n)
    R = ((e * x + x - 1) // (n + 2 * kthp(n, 2) + 1))
    L = ((e * x) // (n + 3 * kthp(n//2, 2) + 1))
    assert y == (L + R) // 2
    assert L == R and isPrime(x) and isPrime(y)
    ## continue as the initial solution