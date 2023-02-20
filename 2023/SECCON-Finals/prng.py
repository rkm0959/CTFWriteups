from sage.all import * 
from pwn import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, getPrime
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Cipher import AES

# Directly taken from rbtree's LLL repository
# From https://oddcoder.com/LOL-34c3/, https://hackmd.io/@hakatashi/B1OM7HFVI
def Babai_CVP(mat, target):
	M = IntegerLattice(mat, lll_reduce=True).reduced_basis
	G = M.gram_schmidt()[0]
	diff = target
	for i in reversed(range(G.nrows())):
		diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
	return target - diff


def solve(mat, lb, ub, weight = None):
	num_var  = mat.nrows()
	num_ineq = mat.ncols()

	max_element = 0 
	for i in range(num_var):
		for j in range(num_ineq):
			max_element = max(max_element, abs(mat[i, j]))

	if weight == None:
		weight = num_ineq * max_element

    # sanity checker
	if len(lb) != num_ineq:
		print("Fail: len(lb) != num_ineq")
		return

	if len(ub) != num_ineq:
		print("Fail: len(ub) != num_ineq")
		return

	for i in range(num_ineq):
		if lb[i] > ub[i]:
			print("Fail: lb[i] > ub[i] at index", i)
			return

    	# heuristic for number of solutions
	DET = 0

	if num_var == num_ineq:
		DET = abs(mat.det())
		num_sol = 1
		for i in range(num_ineq):
			num_sol *= (ub[i] - lb[i])
		if DET == 0:
			print("Zero Determinant")
		else:
			num_sol //= DET
			# + 1 added in for the sake of not making it zero...
			print("Expected Number of Solutions : ", num_sol + 1)

	# scaling process begins
	max_diff = max([ub[i] - lb[i] for i in range(num_ineq)])
	applied_weights = []

	for i in range(num_ineq):
		ineq_weight = weight if lb[i] == ub[i] else max_diff // (ub[i] - lb[i])
		applied_weights.append(ineq_weight)
		for j in range(num_var):
			mat[j, i] *= ineq_weight
		lb[i] *= ineq_weight
		ub[i] *= ineq_weight

	# Solve CVP
	target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
	result = Babai_CVP(mat, target)

	for i in range(num_ineq):
		if (lb[i] <= result[i] <= ub[i]) == False:
			print("Fail : inequality does not hold after solving")
			break
    
    	# recover x
	fin = None

	if DET != 0:
		mat = mat.transpose()
		fin = mat.solve_right(result)
	
	## recover your result
	return result, applied_weights, fin
'''
xs = [four 64 bit numbers]

a, b, c, d, e

xs_n = d * xs_{n-1} + c * xs_{n-2} + b * xs_{n-3} + a * xs_{n-4} + e
=> add 3 numbers here

outs => last 3 numbers

key: first four xs numbers (256 bits) -> mix

a, b, c, d, are known
'''

p = 234687789984662131107323206406195107369
a = 35686285754866388325178539790367732387
b = 36011211474181220344603698726947017489
c = 84664322357902232989540976252462702046
d = 154807718022294938130158404283942212610
outs = [222378874028969090293268624578715626424, 42182082074667038745014860626841402403, 217744703567906139265663577111207633608]
iv = "f2dd287ca870eb9908bf52c44dfd9d2b"
ct = "236a6aca059ae29056a23f5458c644abb74640d672dba1ee049eb956e629b7afb03ae33b2b2b419c24197d33baf6d88e2f0eedfa90c06e1a2be18b2fae2270f05ce39de5e0d59bb9a442d1b3eb392658e45cf721094543b13d35df8cf9ce420c"

'''
xs[0] xs[1] xs[2] xs[3] xs[4] xs[5] xs[6]

<xs[3], e>

xs_n = d * xs_{n-1} + c * xs_{n-2} + b * xs_{n-3} + a * xs_{n-4} + e

xs_{n-4} = (xs_n - d * xs_{n-1} - c * xs_{n-2} - b * xs_{n-3} - e) / a
'''

'''
tt =[7556618114415270298,
8111946174900099316,
17896096178591467897,
9882114333904613878] + outs

key = 0
for x in tt[:4]:
    key <<= 64
    key += x 

key = int(key).to_bytes(32, "little")
cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
print(cipher.decrypt(bytes.fromhex(ct)))


e = GF(p)(tt[6] - a * tt[2] - b * tt[3] - c * tt[4] - d * tt[5])

for i in range(4, 7):
    assert (tt[i] - a * tt[i-4] - b * tt[i-3] - c * tt[i-2] - d * tt[i-1] - e) % p == 0

for i in range(4):
    assert 0 <= tt[i] <= (1 << 64)

'''


coefs = [vector(GF(p), [0] * 3) for i in range(7)]

# xs[3], e, const
coefs[3] = vector(GF(p), [1, 0, 0])

coefs[4] = vector(GF(p), [0, 0, outs[0]])
coefs[5] = vector(GF(p), [0, 0, outs[1]])
coefs[6] = vector(GF(p), [0, 0, outs[2]])


for i in range(2, -1, -1):
    coefs[i] = (coefs[i + 4] - coefs[i + 3] * d - coefs[i + 2] * c - coefs[i + 1] * b - vector(GF(p), [0, 1, 0])) / GF(p)(a)


''' 
coefs[0][0] coefs[1][0] coefs[2][0] coefs[3][0]
coefs[0][1] coefs[1][1] coefs[2][1] coefs[3][1]
p
            p
                    p
'''


'''
0 <= xs[3] <= 2^64
? <= Ae + B xs[3] <= ?


set lattice

Ae + Bxs[3] ~ in some range

xs[3] is in some range
^ in reality this is 0 ~ 2^64

but to enumerate (or pretend to enumerate)

I set this range u * 2^61 ~ v * 2^61
where 0 <= u < v <= 8
'''

for u in range(8):
    for v in range(u + 1, 8):
        M = Matrix(ZZ, 5, 4)
        lb = [0] * 4
        ub = [0] * 4

        for i in range(2):
            for j in range(4):
                M[i, j] = int(coefs[j][i])
        M[2, 0] = p 
        M[3, 1] = p 
        M[4, 2] = p

        for i in range(3):
            lb[i] = p - int(coefs[i][2])
            ub[i] = lb[i] + (1 << 64)

        lb[3] = u << 61
        ub[3] = v << 61

        result, applied_weights, fin = solve(M, lb, ub)

        key = 0

        for i in range(4):
            cc = int(GF(p)(result[i] + coefs[i][2]))
            key <<= 64
            key += cc

        key = int(key).to_bytes(32, "little")

        cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))

        flag = cipher.decrypt(bytes.fromhex(ct))
        if b"SECCON" in flag or b"seccon" in flag:
            print(flag)