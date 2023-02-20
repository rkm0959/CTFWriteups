
from sage.modules.free_module_integer import IntegerLattice

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

# recover p
hint1 = 540914350057159927735436910109553086959907629357396102386062800609858847095404691934517983640846787552171946520460064397364544720996858815571065665255645
hint2 = int.from_bytes(b"Inspired by theoremoon's SECCON 2022 Finals Challenge - Hell. Thank you!", "big")

p = (hint1 + hint2) // (2 * 5 * 8501 * 4823729 * 8561953)

assert p in Primes()
assert (1 << 512) <= p < (1 << 513)

# recover the polynomial: 2 + 3 + 1 = 6 constraints. 6 * 512 >> 8 * 336 so should be enough

PR.<x> = PolynomialRing(GF(p))

C1 = (x^2 + 14762123602851553604749022996287576858980220577795651427829269858766434621297346961387874961427459051934768224338447011128244905975068497090840444625419470*x + 8519674750729750620690035589812482119785861876353468044895414394332293279114303071755954851101633319350193436546144692795403444364414318973131157246232656, 17770738679279057916355557895675090129563269633432826251932824463003364931275912702916209480950481351904761364290424406482997835483807402182326014818733821*x + 12306668467523337827805393760490897581559948654643366727345701375757143864825442910779617850907143245102792529282031529618639723158417652048624567379151171)
C2 = (x^3 + 13441279154284544764330805782065565325543470739559917045273482055514440837785754044182874902421009026981197721504820302867945812937528249594953326223176272*x^2 + 3795282115520834934850220740151212731596814319504043674340537364041453624883995759365119899076774262882230308591629439035308527946872182029742910504122735*x + 3726617245981099594981815385059428688276726297460965450328320328460867196111587736356492934195556032891106446058683147130913147722036293641303193921962091, 2103349591221335944593862709600493681857281410337020721978302326614691696399677635217262732543672829811190387220058078405239568477387817550236173432744263*x^2 + 4784247634355946154999459446762911004042472267922959302672838559247991353014786987556174410735592161587023899368989617780068662559773261109676326152316907*x + 2640959823121300693709616791657128464111647959613642856293592234010564318329382577397798309822254798484629398268742247779165733848105319417195858443049412)
C3 = (x + 540914350057159927735436910109553086959907629357396102386062800609858847095404691934517983640846787552171946520460064397364544720996858815571065665255645, 541917331856005964100090629475512429550322452567752818120774876171019476274441296070275457561095853517207532108745504694853066426720092700847788666013730)
# a[7]x^7 + .... + a[0]x^0 == ??? mod x^3 + ...

# solve for flag1 & flag2 

fin_coefs = []
fin_vec = []

coefs1 = [vector(GF(p), [0] * 8) for _ in range(6)]

for i in range(6):
    coefs1[i][i] = 1

for i in range(5, 1, -1):
    vec = coefs1[i]
    coefs1[i] = 0
    coefs1[i - 1] -= C1[0].coefficients(sparse = False)[1] * vec
    coefs1[i - 2] -= C1[0].coefficients(sparse = False)[0] * vec

rem = (C1[1] ** 2) % C1[0]
for i in range(2):
    fin_coefs.append(coefs1[i])
    fin_vec.append(rem.coefficients(sparse = False)[i])

coefs2 = [vector(GF(p), [0] * 8) for _ in range(8)]

for i in range(8):
    coefs2[i][i] = 1

for i in range(7, 2, -1):
    vec = coefs2[i]
    coefs2[i] = 0
    coefs2[i - 1] -= C2[0].coefficients(sparse = False)[2] * vec
    coefs2[i - 2] -= C2[0].coefficients(sparse = False)[1] * vec 
    coefs2[i - 3] -= C2[0].coefficients(sparse = False)[0] * vec

rem = (C2[1] ** 2) % C2[0]
for i in range(3):
    fin_coefs.append(coefs2[i])
    fin_vec.append(rem.coefficients(sparse = False)[i])

coefs3 = [vector(GF(p), [0] * 8) for _ in range(8)]

for i in range(8):
    coefs3[i][i] = 1

for i in range(7, 0, -1):
    vec = coefs3[i]
    coefs3[i] = 0
    coefs3[i - 1] -= C3[0].coefficients(sparse = False)[0] * vec

rem = (C3[1] ** 2) % C3[0]
fin_coefs.append(coefs3[0])
fin_vec.append(rem.coefficients(sparse = False)[0])

M = Matrix(GF(p), 6, 8)
v = vector(GF(p), fin_vec)

for i in range(6):
    for j in range(8):
        M[i, j] = fin_coefs[i][j]
    
underlying_vector = M.solve_right(v)
basis = M.right_kernel().basis()

M_fin = Matrix(ZZ, 10, 10)
for i in range(2):
    for j in range(8):
        M_fin[i, j] = int(basis[i][j])
    M_fin[i, 8 + i] = 1
for i in range(8):
    M_fin[i + 2, i] = p

lb = [0] * 10
ub = [0] * 10
for i in range(8):
    lb[i] = p - int(underlying_vector[i])
    ub[i] = p + (1 << 336) - int(underlying_vector[i])
for i in range(2):
    lb[i + 8] = 0
    ub[i + 8] = p
result, weights, _ = solve(M_fin, lb, ub)

poly_coefs = []
for i in range(8):
    poly_coefs.append(GF(p)(result[i] // weights[i] + int(underlying_vector[i])))

for i in range(8):
    assert int(poly_coefs[i]) <= (1 << 336)
F1 = 0 
for i in range(6):
    F1 += (x ** i) * poly_coefs[i]
F2 = 0
for i in range(8):
    F2 += (x ** i) * poly_coefs[i]

assert (F1 - C1[1] * C1[1]) % C1[0] == 0
assert (F2 - C2[1] * C2[1]) % C2[0] == 0
assert (F2 - C3[1] * C3[1]) % C3[0] == 0

print(p)
print(F1)
print(F2)
