from sage.all import * 
from Crypto.Util.number import *

from sage.modules.free_module_integer import IntegerLattice

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

ctxt = 115139400156559163067983730101733651044517302092738415230761576068368627143021367186957088381449359016008152481518188727055259259438853550911696408473202582626669824350180493062986420292176306828782792330214492239993109523633165689080824380627230327245751549253757852668981573771168683865251547238022125676591

p = 8200291410122039687250292442109878676753589397818032770561720051299309477271228768886216860911120846659270343793701939593802424969673253182414886645533851

shares = [((6086926015098867242735222866983726204461220951103360009696454681019399690511733951569533187634005519163004817081362909518890288475814570715924211956186561, 180544606207615749673679003486920396349643373592065733048594170223181990080540522443341611038923128944258091068067227964575144365802736335177084131200721), 358596622670209028757821020375422468786000283337112662091012759053764980353656144756495576189654506534688021724133853284750462313294554223173599545023200), ((1386358358863317578119640490115732907593775890728347365516358215967843845703994105707232051642221482563536659365469364255206757315665759154598917141827974, 4056544903690651970564657683645824587566358589111269611317182863269566520886711060942678307985575546879523617067909465838713131842847785502375410189119098), 7987498083862441578197078091675653094495875014017487290616050579537158854070043336559221536943501617079375762641137734054184462590583526782938983347248670), ((656537687734778409273502324331707970697362050871244803755641285452940994603617400730910858122669191686993796208644537023001462145198921682454359699163851, 7168506530157948082373212337047037955782714850395068869680326068416218527056283262697351993204957096383236610668826321537260018440150283660410281255549702), 1047085825033120721880384312942308021912742666478829834943737959325181775143075576517355925753610902886229818331095595005460339857743811544053574078662507), ((5258797924027715460925283932681628978641108698338452367217155856384763787158334845391544834908979711067046042420593321638221507208614929195171831766268954, 4425317882205634741873988391516678208287005927456949928854593454650522868601946818897817646576217811686765487183061848994765729348913592238613989095356071), 866086803634294445156445022661535120113351818468169243952864826652249446764789342099913962106165135623940932785868082548653702309009757035399759882130676)]

assert isPrime(p) # p = 512 bit

M = Matrix(ZZ, 11, 11)
lb = [0] * 11
ub = [0] * 11

for i in range(4):
    M[0, i] = shares[i][0][0]
    M[1, i] = (shares[i][0][0] ** 2) % p
    M[2, i] = (shares[i][0][0] ** 3) % p 
    M[3, i] = shares[i][0][1]
    M[4, i] = (shares[i][0][1] ** 2) % p
    M[5, i] = (shares[i][0][1] ** 3) % p 
    M[6, i] = 1
    M[7 + i, i] = p
    lb[i] = shares[i][1] - (1 << 256)
    ub[i] = shares[i][1]

M[0, 4] = 1
M[1, 5] = 1
M[2, 6] = 1
M[3, 7] = 1
M[4, 8] = 1
M[5, 9] = 1
M[6, 10] = 1

for i in range(4, 11):
    lb[i] = 0
    ub[i] = 1 << 128

result, applied_weights, fin = solve(M, lb, ub)

coeffs = [0] * 8

for i in range(6):
    coeffs[i] = int(fin[i])

new_share = [0] * 4

for i in range(4):
    new_share[i] = shares[i][1]
    for j in range(3):
        new_share[i] -= coeffs[j] * (shares[i][0][0] ** (j + 1))
        new_share[i] -= coeffs[j + 3] * (shares[i][0][1] ** (j + 1))
    new_share[i] %= p
    new_share[i] = int(new_share[i])

# c * z[i] + s = new_share[i]
c = 0
for i in range(3):
    diff = new_share[i] - new_share[i + 1]
    c = GCD(c, diff)

coeffs[6] = c

coeffs[7] = new_share[0] % c

key = 0
for coeff in coeffs:
    key <<= 128
    key ^= coeff

flag = ctxt ^ key 

print(long_to_bytes(flag))