## modified https://github.com/ubuntor/coppersmith-algorithm/blob/main/coppersmith.sage
 
debug = True
 
N = 123463519828344660835965296108959625188149729700517379543746606603601816029557213728343115758280318474617032830851553509268562367217512005079977122560679743955588214135519642513042848616372204042776892196887455692479457740367547908255044784496969010537283159300508751036032559594474145098337531029291955103059
e = 85803665824396212221464259773478155183477895540333642019501498374139506738444521180470104195883386495607712971252463223185914391456070458788554837326327618859712794129800329295751565279950274474800740076285111503780662397876663144946831503522281710586712396810593754749589799811545251575782431569881989690861
gift = 46710143823773072238724337855139753113453277386728402328859555407710009799097841900723288768522450009531777773692804519189753306306645410280934372812
enc = 106121451638162677594573310940827829041097305506084523508481527070289767121202640647932427882853090304492662258820333412210185673459181060321182621778215705296467924514370932937109363645133019461501960295399876223216991409548390823510949085131028770701612550221001043472702499511394058569487248345808385915190
 
delta = 0.6
gamma = 120 / 1022
lam = max(gamma, delta - 0.5)
d_0 = (gift << 120) + (1 << 119) 
k_0 = (e * d_0 - 1) // N
X = (int)(4 * (N ** lam))
Y = (int)(3 * ((N/2) ** 0.5))
m = 5
t = 3
 
P.<x,y> = PolynomialRing(ZZ)
pol = (1 + k_0 * N) % e + (k_0 % e) * y + (N % e) * x + x * y
 
while gcd(pol(0,0), X) != 1:
    X = next_prime(X, proof=False)
 
while gcd(pol(0,0), Y) != 1:
    Y = next_prime(Y, proof=False)
 
polynomials = []
for j in range(0, m+1):
    for i in range(0, m-j+t+1):
        polynomials.append(x^i * pol^j * e^(m-j))
for j in range(0, m+1):
    for i in range(1, m-j+1):
        polynomials.append(y^i * pol^j * e^(m-j))
 
monomials = []
for i in polynomials:
    for j in i.monomials():
        if j not in monomials:
            monomials.append(j)
monomials.sort()
 
L = matrix(ZZ,len(monomials))
for i in range(len(monomials)):
    for j in range(len(monomials)):
        L[i,j] = polynomials[i](X*x,Y*y).monomial_coefficient(monomials[j])
 
L = matrix(ZZ,sorted(L,reverse=True))
L = L.LLL()
roots = []
 
for i in range(L.nrows()):
    for j in range(i+1, L.nrows()):
        pol1 = P(sum(map(mul, zip(L[i],monomials)))(x/X,y/Y))
        pol2 = P(sum(map(mul, zip(L[j],monomials)))(x/X,y/Y))
        r = pol1.resultant(pol2, y)
        if r.is_constant():
            continue
        for x0, _ in r.univariate_polynomial().roots():
            if x0 in [i[0] for i in roots]:
                continue
            if debug:
                print("Potential x0:",x0)
            for y0, _ in pol1(x0,y).univariate_polynomial().roots():
                if debug:
                    print("Potential y0:",y0)
                if (x0,y0) not in roots:
                    roots.append((x0,y0))
print(roots)