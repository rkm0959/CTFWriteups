p = 64050696188665199345192377656931194086566536936726816377438460361325379667067
 
def MAT(X):
    M = Matrix(GF(p), 5, 5)
    cnt = 0 
    for i in range(0, 5):
        for j in range(0, 5):
            M[i, j] = X[cnt]
            cnt += 1
    return M
 
G = 
A = 
B = 
 
GMAT = MAT(G)
AMAT = MAT(A)
BMAT = MAT(B)
 
print(GMAT.charpoly().factor())
print(AMAT.charpoly().factor())
print(BMAT.charpoly().factor())
 
 
J, P = GMAT.jordan_form(transformation = True)
AMAT = P^-1 * AMAT * P
BMAT = P^-1 * BMAT * P
print(J)
print("")
print(AMAT)
print("")
print(BMAT)
 
print(AMAT[3, 4] / AMAT[3, 3] * J[3, 3]) # dlog
print(BMAT[3, 4] / BMAT[3, 3] * J[3, 3]) # dlog
# the rest is relatively trivial (get shared secret, decrypt flag)