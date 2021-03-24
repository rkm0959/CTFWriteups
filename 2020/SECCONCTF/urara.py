K = Zmod(n)
P.<x> = PolynomialRing(K, implementation='NTL')
f = (3 * x^2 + a)^2 - (2*x + Qx) *(4*(x^3 + a*x+b))
g = power_mod(x + t, 65537, f) - c
print(GCD(f, g, n))
## the remaining details are trivial