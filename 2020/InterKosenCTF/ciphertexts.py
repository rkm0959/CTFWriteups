r = n2 // n1
d = inverse(e2, r - 1)
mr = pow(c2, d, r)
d1 = inverse(e1, e2)
d2 = (e1 * d1 - 1) // e2
mn1 = pow(c1, d1, n1) * inverse(pow(c2, d2, n1), n1) % n1
u, v = CRT(mn1, n1, mr, r)
print(long_to_bytes(u))
