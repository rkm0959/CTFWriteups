import os 
from Crypto.Util.number import long_to_bytes
import time 

st = time.time()

p = 20206629497318640302613717177493021659164910368667008120702312168658959729889280963268869447056316491892128508524975162223724948508181049113205403468161303
PR.<x> = PolynomialRing(GF(p))

f = 66742610447429428817366180707200350235291618033097320626893666201036423466905593223128856596517455039*x^5 + 63031675848430017482485880342955884769291566790271002334095611361178377204121055898553769655572802998*x^4 + 73551004247039298713506464216106486832855555473943539450955116084581822047116438494052971492741787353*x^3 + 103980310160513080155264590773421419484053537304074203924614986854547620459142032682836298957636074146*x^2 + 100530104457775034008443059788814962668335386078661701461256355711423064081802002152448681318698671065*x + 74749876241725972625141395620386798947434400296543717231503622934162104749079408980985018578978951986

lmao = (x^2 + 14762123602851553604749022996287576858980220577795651427829269858766434621297346961387874961427459051934768224338447011128244905975068497090840444625419470*x + 8519674750729750620690035589812482119785861876353468044895414394332293279114303071755954851101633319350193436546144692795403444364414318973131157246232656, 17770738679279057916355557895675090129563269633432826251932824463003364931275912702916209480950481351904761364290424406482997835483807402182326014818733821*x + 12306668467523337827805393760490897581559948654643366727345701375757143864825442910779617850907143245102792529282031529618639723158417652048624567379151171)

fc = f.coefficients(sparse = False)
lmaoc = lmao[0].coefficients(sparse = False)

X, A, B, C, D = GF(p)['X,A,B,C,D'].gens()

VAL = (A + B * X + C * X * X + X * X * X) ** 2 - (fc[0] + fc[1] * X + fc[2] * X * X + fc[3] * X * X * X + fc[4] * X * X * X * X + fc[5] * X * X * X * X * X) * D

Is = [0] * 5
for i in range(6, 1, -1):
    Is[i - 2] = VAL.coefficient({X: i})
    VAL -= (X ** i) * Is[i - 2]
    VAL += (X ** (i - 2)) * (-lmaoc[1] * X - lmaoc[0]) * Is[i - 2]

DV0 = VAL.coefficient({X: 0})
DV1 = VAL.coefficient({X: 1})

V = Is[2] / GF(p)(2) - Is[3] * Is[3] / GF(p)(8)

SQ0 = V * Is[3] - Is[1]
SQ1 = V * V - Is[0]

RES1 = DV0.sylvester_matrix(DV1, A).determinant()
RES2 = DV0.sylvester_matrix(SQ0, A).determinant()
RES3 = DV0.sylvester_matrix(SQ1, A).determinant()

print("done1")

RES4 = RES1.sylvester_matrix(RES2, B).determinant()
RES5 = RES1.sylvester_matrix(RES3, B).determinant()

print("done2")

RES6 = RES4.sylvester_matrix(RES5, C).determinant()

print("done3")

from tqdm import tqdm

def reduction(F, VAR):
    ret = 0
    tt = F.monomials()
    vals = F.coefficients()
    for i in range(len(tt)):
        ret += (x ** (tt[i].degree())) * vals[i]
    return ret

func_d = reduction(RES6, D)

roots_d = func_d.roots()

for fin_d, exd in tqdm(roots_d):
    func_c1 = reduction(RES4.subs({D: fin_d}), C)
    func_c2 = reduction(RES5.subs({D: fin_d}), C)
    func_c = func_c1.gcd(func_c2)
    roots_c = func_c.roots()
    for fin_c, exc in roots_c:
        func_b1 = reduction(RES1.subs({D: fin_d, C: fin_c}), B)
        func_b2 = reduction(RES2.subs({D: fin_d, C: fin_c}), B)
        func_b3 = reduction(RES3.subs({D: fin_d, C: fin_c}), B)
        func_b = func_b1.gcd(func_b2).gcd(func_b3)
        roots_b = func_b.roots()
        for fin_b, exb in roots_b:
            func_a1 = reduction(DV0.subs({D: fin_d, C: fin_c, B: fin_b}), A)
            func_a2 = reduction(DV1.subs({D: fin_d, C: fin_c, B: fin_b}), A)
            func_a3 = reduction(SQ0.subs({D: fin_d, C: fin_c, B: fin_b}), A)
            func_a4 = reduction(SQ0.subs({D: fin_d, C: fin_c, B: fin_b}), A)
            func_a = func_a1.gcd(func_a2).gcd(func_a3).gcd(func_a4)
            roots_a = func_a.roots()
            for fin_a, exa in roots_a:
                FIN = (fin_a + fin_b * x + fin_c * x * x + x * x * x) ** 2 - f * fin_d
                FIN //= lmao[0]
                fac = list(FIN.factor())
                print(fac)
                if len(fac) == 2 and fac[0][1] == 2 and fac[1][1] == 2:
                    val1 = p - int(fac[0][0].coefficients(sparse=False)[0])
                    val2 = p - int(fac[1][0].coefficients(sparse=False)[0])
                    print(long_to_bytes(val1))
                    print(long_to_bytes(val2))
                    print(long_to_bytes(p - val1))
                    print(long_to_bytes(p - val2))

en = time.time()

print(en - st)
