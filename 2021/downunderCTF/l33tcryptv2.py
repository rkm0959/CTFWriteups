from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Cipher import AES, ARC4, DES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

def inthroot(a, n):
	return a.nth_root(n, truncate_mode=True)[0]

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

	m = mat * mat.transpose()
	DET = inthroot(Integer(m.det()), 2)
	num_sol = 1
	for i in range(num_ineq):
		num_sol *= (ub[i] - lb[i])
	if DET == 0:
		print("Zero Determinant")
	else:
		num_sol //= DET
		# + 1 added in for the sake of not making it zero...
		# print("Expected Number of Solutions : ", num_sol + 1)
		# print(num_sol+1)

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
			# print("Fail : inequality does not hold after solving")
			return None, None, None
			break
	
		# recover x
	fin = None

	mat = mat.transpose()
	fin = mat.solve_right(result)
	
	## recover your result
	return result, applied_weights, fin

hint1 = 9474114456792673515431877947943819508105969635542281515830563486137327168661333703401850605206493227243522275742966516648683239582868203596838274343178793480973891177607186024817920580636526398124249438530268326706106084200991464054888550590630591134888356623254262308517945404542523082470069480353068223694311508861801523183513245279545596528410382012946385366699431483305340128165852371328697376926968446708099825429442186214124021086080153564030893750081986851543881131351556953787562383902563532279388285764786107301410609469955447888060120474186646198067390958666731078269768973485409216649415321100676385488676994332545669638759522053210552702128133338413305324201806761866164474398103381334477039479224259925086453057512169480806903881772813089475880157326511289464083589335128877565750510634618850
hint2 = [(732546382458694012527789828012658378094702844241795401426843533262220812770028735455197287163119092985574791815396084039371039996745646333674579318749988785972110472195404257454757344814442424493794011566431937242360848878285030166984149693743077380791443878087350475749876855340312637158554338528312647367781264029940556029591883509296327157870585105957528288777977912893801651347425601258985587330670953298765350018187069720989197539655266126608555068568433785671130844623376557756307700624321155540004939237651224429899583558320317618753120682478549822994855115229255313084828494729871333964260804633974731539710591594817406548163223896591957023800247556355776277803866504762994363248426088927388107745396346246364269053285330511504658050763844166012473791572894552857353549047649195624795947489180260979461063462063828112399114859364813704521025921163040319096254633472956309716047137099678802685979113668885601296025318218875502044310139823328365450929054463143898168438742821823709383772324178942782797995009228644990630313338092741812684409459706859981433655900653533420603781201785114071059836464490109704785152549161122683211537057829631974746267465106271003835623120675868336217957493577419646574917016786960763971105924313670864643113152080247596101761667919974877317059734430884155146853783807463171001928603696124835265895296591581488900411484570933812177545618929573489183920330986109459899431831015221573294655414274883012371358092609067769905057144741729285256290725546405447624734438623235233946301969480294721959115680856021696640872884026385162811995627855934793386619910476937700613082779, 1543824598221623810544208805328287421613768036151947874139391287620165680044273642997713684429385602196228549596953402195253771549624806908757244012787647676921740972118119690619160814867773301029620094485726996907379061963500831983371578370700427374066341469843386724329442101058337650126328673673103875588454070821764869582749550357448526278027673495765146251605639297850930361919443005623694632013303, 278066231056905142305104802223227529510107823582373063981133703297010715328189269872672545717708004188569473458656648620603642909190690880317856689557616399347538953740829444695466029704435732263108744727780955070759083273384356847390585190707938226562580173928509689922077486197504519480359398971760153208230160873276281036727480009843280457680277644007154868247812957266590582948212002647347579597965), (2403931462615300014912573083791207269120927941165936946270714147348589275302782927254153349406751900409737005652653965419293500156635383418370534229776798159799544655491444625223239629070116271649566531509751492007287556686610922243146922720689240769956444136141045389983487722510967341333296316124861289680453311483583713394680884118860739515747245777714794715741583447733115461680095467478792575220154609730018111981467052398055564596522296491712770565301016865613056558617018826541540034369006769600336871572325043701351770219492587170369815095344397680717819930616599208355365092147396589419063661351495695927808384696467907751578957796331366383391221037004742878990846671674314297157060496951084267550785175020195260374151822097301166545332365173007130667658669023236685137146454027881996654859397883138679620794416770836903293285267689375186032800923071081877797299448490161970114063577601307797826188431113415671273120884557490666872780316977507218882738147619244927641770516473541881268874031321080906148751514801419469523784406736104695838521768957591700470012632981881278541917424550592192054960270762406248837436552253011562745897713476468254217503340327771690937113342506707740878371307784138197357653258554320947445665637325825934844545591362876466794093523698691499245458580590045390833227060694376995243735824822120025136206595444317852707366827787780703456414342309744435791623414331744392284997640092463157849832124166944965921884701468913065315740226664124591175781629426506057267248659303310396227692666112080517619152746622372541984530565220811971391954114052398015660212010257113648848847, 1095271776133890944180744243712910546278746562392568011876271303881431329832093376635925871119446466987231888845639447279594831752278087660346437418402997861987783151298417098367490883057794520011454228160352569059415183920272078930149476192223454197039306461996527833603604938471295363667754643414137116188016150205603690898270274189826416464265752825558069478170856048769787582750749123139364050774900, 503722937364073120219172142862403799517933100630972300242952550817433776953552478694914014362767990852845981728951892566080540126804572527879551832311854342967959495035585119889481210539549990451963720802920003582648892828543694739151645941765335597098334960962085798952240875279321239403245884262371088975882015803767312665173035156867269826854927631774910426072984288933637519024572470691768302645082)]
c = 605102888419960227209554020321928680123927287488855374705023014664876415212834812004489811277243459845970579234661036307883657755039678491432326372452841243321229852171896023071850921050801342321482817352489245753590859528134913389224781053767643398051814697896895555141791201522215484812840325201515942495422062613986130075684389632368804195932004897586630630338128732739336582396560286087433253207646470438321442025408149861408487622053608073870706373371068091196032798889074109310838175523351596714632562756238346928415386196418507587810202943766172435188745498284802679701385932344117910084137055452834777639122479568560833213921960536746001563295384313906616645378042076612734674897406388665158992742560848871345048141300064428115232029157294890916882227084289355920878535418217759491272196240289158*I + 4029058763453606238903897463441562834907249422434463474076515876575829847522130192389016587404930865750330557087612323698180248796377295462524538856886086398759909290696184205993616487194215215220788562122976961077906744617472657126002125275580071372330371116294688544107523683271239033324714979085342248973341926663953843846046960739886947485863993625451601367382937578510847100654709310703410238862000749364014455073705910890023184023421059288913438268024784676942709153616462894290327611033397199003399769315399282676125251796552761022560343255167268538619398474794249565056809687349530329863724341722260050648912909130315084736439621962322946883555665867960336853966064629555225967168666632969614488585135849531033105444785970372310095381763641123031809302021416125564151419362313796375570121725315170
l = 338

offset = 3

M = Matrix(ZZ, 3, 4)
lb = [0] * 4
ub = [0] * 4

y1, a1, b1 = hint2[0]
y2, a2, b2 = hint2[1]

target1 = (y1 // hint1 - b1 * b1) * (1 << (l-1)) * hint1
fx = hint1 * (1 << (l-1))

M[0, 0] = a1 * b1 * (1 << l)
M[1, 0] = hint1 * b1 
lb[0] = target1 - offset * fx 
ub[0] = target1 

target2 = (y2 // hint1 - b2 * b2) * (1 << (l-1)) * hint1 

M[0, 1] = a2 * b2 * (1 << l)
M[2, 1] = hint1 * b2
lb[1] = target2 - offset * fx
ub[1] = target2

M[1, 2] = 1
lb[2] = 0
ub[2] = 1 << l

M[2, 3] = 1
lb[3] = 0
ub[3] = 1 << l

result, applied_weights, fin = solve(M, lb, ub)

p = next_prime(int(fin[0]))
q = inthroot(Integer(hint1 - p * p), 2)

print(p * p + q * q - hint1)

'''
phi = (p * p - 1) * (q * q - 1)
d = int(inverse_mod(0x1337, phi))
n = p * q
Zn.<I> = (ZZ.quo(n*ZZ))[]
ZnI.<I> = Zn.quo(I^2 + 1)
c = 605102888419960227209554020321928680123927287488855374705023014664876415212834812004489811277243459845970579234661036307883657755039678491432326372452841243321229852171896023071850921050801342321482817352489245753590859528134913389224781053767643398051814697896895555141791201522215484812840325201515942495422062613986130075684389632368804195932004897586630630338128732739336582396560286087433253207646470438321442025408149861408487622053608073870706373371068091196032798889074109310838175523351596714632562756238346928415386196418507587810202943766172435188745498284802679701385932344117910084137055452834777639122479568560833213921960536746001563295384313906616645378042076612734674897406388665158992742560848871345048141300064428115232029157294890916882227084289355920878535418217759491272196240289158*I + 4029058763453606238903897463441562834907249422434463474076515876575829847522130192389016587404930865750330557087612323698180248796377295462524538856886086398759909290696184205993616487194215215220788562122976961077906744617472657126002125275580071372330371116294688544107523683271239033324714979085342248973341926663953843846046960739886947485863993625451601367382937578510847100654709310703410238862000749364014455073705910890023184023421059288913438268024784676942709153616462894290327611033397199003399769315399282676125251796552761022560343255167268538619398474794249565056809687349530329863724341722260050648912909130315084736439621962322946883555665867960336853966064629555225967168666632969614488585135849531033105444785970372310095381763641123031809302021416125564151419362313796375570121725315170
print(pow(c, d))
'''