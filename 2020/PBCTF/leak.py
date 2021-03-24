def Babai_closest_vector(M, G, target):
        small = target
        for _ in range(1):
            for i in reversed(range(M.nrows())):
                c = ((small * G[i]) / (G[i] * G[i])).round()
                small -=  M[i] * c
        return target - small 
 
NUM = 10
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
SIG = [] ## signature
 
M = Matrix(ZZ, 3 * NUM + 1, 3 * NUM + 1)
for i in range(0, NUM):
    M[0, i] = SIG[i][2] * n * n
M[0, NUM] = 1
 
for i in range(0, NUM):
    M[2 * i + 1, i] = (2 ** 216) * SIG[i][3] * n * n
    M[2 * i + 2, i] = SIG[i][3] * n * n
    M[2 * i + 1, NUM + 2 * i + 1] = n // (2 ** 40)
    M[2 * i + 2, NUM + 2 * i + 2] = n // (2 ** 40)
for i in range(0, NUM):
    M[2 * NUM + 1 + i, i] = n * n * n
Target = [0] * (3 * NUM + 1)
for i in range(0, NUM):
    Target[i] = ((SIG[i][1] * (2 ** 40) * SIG[i][3] - SIG[i][0]) % n) * n * n
Target = vector(Target)
M = M.LLL()
GG = M.gram_schmidt()[0]
TT = Babai_closest_vector(M, GG, Target)
print(TT - Target)
print(TT[NUM] % n) ## secret
