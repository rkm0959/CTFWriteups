def Babai_closest_vector(M, G, target):
        small = target
        for _ in range(1):
            for i in reversed(range(M.nrows())):
                c = ((small * G[i]) / (G[i] * G[i])).round()
                small -=  M[i] * c
        return target - small 

## Step 1 : Factorization of N

rat = 2 ** 1000 
## scaling : super large to force zero in the first column
 
for i in range(0, 9):
    M[i, 0] = (3 ** (66 * i)) * rat
M[9, 0] = n * rat
for i in range(0, 9):
    M[i, i+1] = 1

Target = [0] * 10
for i in range(1, 10):
    Target[i] = (2 ** 64)
 
M = M.LLL()
GG = M.gram_schmidt()[0]
Target = vector(Target)
TT = Babai_closest_vector(M, GG, Target)
 
P.<x> = PolynomialRing(ZZ)
f = 0
for i in range(1, 10):
    f = f + TT[i] * x^(i-1)

print(f.factor())
## (2187594805*x^4 + 2330453070*x^3 + 2454571743*x^2 + 2172951063*x + 3997404950) 
## (3053645990*x^4 + 3025986779*x^3 + 2956649421*x^2 + 3181401791*x + 4085160459)
 
cc = 0
cc += 2187594805 * (3 ** (66 * 4))
cc += 2330453070 * (3 ** (66 * 3))
cc += 2454571743 * (3 ** (66 * 2))
cc += 2172951063 * (3 ** (66 * 1))
cc += 3997404950 * (3 ** (66 * 0))
 
p = gcd(cc, n)
print(p)
print(n // p)
print(n % p)
 
## Step 2 : housekeeping stuff
## res in res.txt, A in A.npy

p = 122286683590821384708927559261006610931573935494533014267913695701452160518376584698853935842772049170451497
q = 268599801432887942388349567231788231269064717981088022136662922349190872076740737541006100017108181256486533
e = 127
n = p * q
phi = (p-1) * (q-1)
d = inverse(e, phi)
 
cv = []
for x in res:
    cv.append(pow(x, d, n))
 
print(cv)
 
A = np.load("A.npy")
A = np.ndarray.tolist(A)

## Step 3 : LWE with CVP
mod = 152989197224467
 
sel = 15 ## sel can be large as 127, but that's too slow
M = Matrix(ZZ, sel + 43, sel + 43)
for i in range(0, 43):
    for j in range(0, sel):
        M[i, j] = A[j][i]
    M[i, sel + i] = 1
for i in range(43, 43+sel):
    M[i, i-43] = mod
Target = [0] * (sel + 43)
for i in range(0, sel):
    Target[i] = cv[i] - 8
for i in range(sel, sel + 43):
    Target[i] = 80 ## printable
 
Target = vector(Target)
M = M.LLL()
GG = M.gram_schmidt()[0]
Target = vector(Target)
TT = Babai_closest_vector(M, GG, Target)
 
print(TT)
 
res = ""
for i in range(sel, sel+43):
    res += chr(TT[i])
 
print(res)