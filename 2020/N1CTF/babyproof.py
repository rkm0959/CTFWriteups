d = 60 ## get 60 instances
M = Matrix(ZZ, d+1, d+1)
for i in range(0, d):
    M[0, i] = cs[i]
M[0, d] = 1
for i in range(0, d):
    M[i+1, i] = qs[i]
 
Target = [0] * (d+1)
for i in range(0, d):
    Target[i] = (2 ** 246) - rs[i]
Target[d] = (2 ** 246)
 
M = M.LLL()
GG = M.gram_schmidt()[0]
Target = vector(Target)
TT = Babai_closest_vector(M, GG, Target)
 
x = TT[d]
print(x)
print(bytes.fromhex(hex(x)[2:]))