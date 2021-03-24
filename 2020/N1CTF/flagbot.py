cur_mod = 1
cur_val = 0
 
for i in range(0, 7):
    a = S[i][0]
    b = S[i][1]
    p = S[i][2]
    E = EllipticCurve(GF(p), [a, b])
    Ord = E.order()
    L = list(factor(Ord))
    GG = E(g[i])
    SS = E(S_pub[i])
    for pp, dd in L:
        if pp <= 10 ** 12 and dd == 1:
            Gp = (Ord // pp) * GG
            Sp = (Ord // pp) * SS
            tt = discrete_log(Sp, Gp, operation='+')
            cur_val = crt(cur_val, tt, cur_mod, pp)
            cur_mod = (cur_mod * pp) // gcd(pp, cur_mod)
    print("Done ", i)
    
print("[+] Secret: ", cur_val)

# check
for i in range(0, 7):
    a = S[i][0]
    b = S[i][1]
    p = S[i][2]
    E = EllipticCurve(GF(p), [a, b])
    RR = E(R_pub[i])
    RES = RR * cur_val
    print(RES.xy()[0])
