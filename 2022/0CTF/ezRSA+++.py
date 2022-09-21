from sage.all import * 
import random as rand
from tqdm import tqdm 
import time 
from Crypto.Util.number import inverse, getPrime 

p_size = 1000
d_size = 105
l_size = 55

enc = 35558284230663313298312684064040643811204702946900174110911295087662938676356112802781671547473910691476600838877279843972105403072929243674403244286458898562457747942651643439624568905004454158744508429126554955023110569348839934098381885098523538078300248638407684468503519326866276798222721018258242443186786917829878515320321445508466038372324063139762003962072922393974710763356236627711414307859950011736526834586028087922704589199885845050751932885698053938070734392371814246294798366452078193195538346218718588887085179856336533576097324041969786125752304133487678308830354729347735644474025828

pk = (44774502335951608354043148360684114092901940301155357314508676399067538307546121753785009844275454594381602690061553832466871574728524408152400619047820736137949166290404514747591817206669966103047443912935755873432503095952914080827536130899968275165557303493867755627520568588808534411526058896791373252974606364861105086430729757064078675811147972536205086402752245214343186536177015741922559575575911278873118556603923689408629477875537332177644886701517140711134017511229202430437068095342526435886609381176269251580339549071944830141516001532825295594908434587285225415103472279090325281062442217, 29624366183227462965645558392954094074485353876807451497147549927093025197118051280445930543762170853769573962200247669305286333212410439624262142109295839433584663989554419810341266820063074908743295553517790354149623873028162282751352613333181218478850463012413786673509078012976454604598813805735677104174112776060905225493357010861225261560490401501912259585922988353328944884443953564154752191932500561561256069872534626325000901099904014035414792860997025614313564862063784602254606240743545483125618939111639728114664995759380293512809125885893543730614962375399353971677980309835647540883700977)

hint = (5013415024346389, 4333469053087705)


(n, e) = pk
(hint_p, hint_q) = hint

SIZE = 1 << ((d_size - l_size) // 2)
m = Zmod(n)(rand.randint(2, 1 << 128))
print("m", int(m))

RR = Zmod(n)

chirp = m ** (e << l_size)
Fix1 = m ** (e * hint_p)
Fix2 = m ** (e << ((l_size + d_size) // 2))

sys.setrecursionlimit(10 ** 6)

P = PolynomialRing(RR, 'x')
x = P.gen()

T = time.time()

cnt = 0 

DEG_BOUND = (1 << 24)

def getMul(f1, f2):
    if f1.degree() < DEG_BOUND and f2.degree() < DEG_BOUND:
        return f1 * f2
    arr = [RR(0)] * (f1.degree() + f2.degree() + 1)
    temp1 = f1.coefficients(sparse = False)
    temp2 = f2.coefficients(sparse = False)
    idx1 = 0
    U1s = []
    while idx1 <= f1.degree():
        U1s.append(P(temp1[idx1: idx1 + DEG_BOUND]))
        idx1 += DEG_BOUND 
    idx2 = 0
    U2s = []
    while idx2 <= f2.degree():
        U2s.append(P(temp2[idx2: idx2 + DEG_BOUND]))
        idx2 += DEG_BOUND
    idx1, idx2 = 0, 0
    while idx1 * DEG_BOUND <= f1.degree():
        idx2 = 0
        while idx2 * DEG_BOUND <= f2.degree():
            temp = (U1s[idx1] * U2s[idx2]).coefficients(sparse = False)
            for v in range(len(temp)):
                arr[(idx1 + idx2) * DEG_BOUND + v] += temp[v]
            idx2 += 1
        idx1 += 1
    return P(arr)

def compute(L, R):
    global cnt
    if R - L == (1 << 16):
        print("HEY", cnt)
        cnt += 1
    if L >= R:
        return 1 
    if L + 1 == R:
        return ((Fix2 ** L) * Fix1) * x - m
    f1 = compute(L, (L + R) // 2)
    f2 = compute((L + R) // 2, R)
    return getMul(f1, f2)

G = compute(0, SIZE)

print(time.time() - T)

# now compute all 
print("computed G(x), now multipoint eval via chirp-z")

coefG = G.coefficients(sparse = False)

del G 

A1 = [RR(1), RR(1)]
cur = RR(1)
for i in tqdm(range(2, SIZE * 2)):
    cur = cur * chirpwa
    A1.append(A1[i-1] * cur)

A0 = []
for i in tqdm(range(SIZE + 1)):
    A0.append(coefG[SIZE - i] / A1[SIZE - i])

del coefG


idx1 = 0
U1s = []
while idx1 <= SIZE:
    U1s.append(P(A0[idx1: idx1 + DEG_BOUND]))
    idx1 += DEG_BOUND 
del A0 

print("A0")


idx2 = 0
U2s = []
while idx2 <= SIZE * 2 - 1:
    U2s.append(P(A1[idx2: idx2 + DEG_BOUND]))
    idx2 += DEG_BOUND

print("A1")

arr = [RR(0)] * (SIZE)
idx1, idx2 = 0, 0
while idx1 * DEG_BOUND <= SIZE:
    idx2 = 0
    while idx2 * DEG_BOUND <= SIZE * 2 - 1:
        temp = (U1s[idx1] * U2s[idx2]).coefficients(sparse = False)
        for v in range(len(temp)):
            if SIZE <= (idx1 + idx2) * DEG_BOUND + v < 2 * SIZE:
                arr[(idx1 + idx2) * DEG_BOUND + v - SIZE] += temp[v]
        del temp 
        idx2 += 1
    idx1 += 1

print("now let's calculate it!")

for i in tqdm(range(0, SIZE)):
    val = arr[i] / A1[i]
    t = GCD(int(val), n)
    if t != 1 and t != n:
        print("Found!!!!", t)

print(time.time() - T)