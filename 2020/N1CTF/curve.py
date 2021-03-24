# parameter generation only : for server interaction, read writeup

pr = []
for x in range(50, 200):
    if x in Primes():
        pr.append(x)
while True:
    p = random_prime(2 ** 512, False, 2 ** 511)
    if p % 3 == 2: ## in this case, y^2 = x^3 + b is guaranteed to be supersingular
        continue
    d = randint(1, p-1)
    E = EllipticCurve(GF(p), [0, d])
    if E.is_supersingular() == True:
        continue
    print(p)
    L = E.order()
    for cc in pr:
        if L % cc == 0:
            print(p, d, cc, L)
            break
 
## find any point on the elliptic curve
for u in range(1, 100):
    goal = (u ** 3 + a * u + b) % p
    if pow(goal, (p-1) // 2, p) == 1:
        v = tonelli(goal, p) ## sqrt, so you can directly use sage
        G = E(u, v)
        break
 
## hope that G is nonzero
G = G * (Ord // pr)
G1 = G
G2 = G
 
## this ends parameter generation
