from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice

context.log_level = "error"

DIF16 = [55307, 2592, 8216, 39038, 16351, 8021, 5419, 27443, 45978, 7098, 47652, 26023, 26509, 52619, 51731, 53785, 6200, 63521, 41054, 24448, 32980, 22014, 65228, 36183, 22252, 11465, 35183, 12003, 9065, 10619, 15203, 58202, 56186, 47909, 9380, 25713, 61838, 53059, 33301, 5368, 63536, 45406, 24508, 48340, 21934, 44748, 36247, 38636, 60872, 2413, 44317, 40082, 37840, 53700, 1341, 15628, 19539, 54254, 44859, 14996, 21593, 6607, 20258, 25323, 43911, 50843, 39432, 51673, 55324, 7456, 57389, 27775, 32656, 4266, 59967, 32359, 42921, 10378, 35424, 57830, 59260, 48501, 46253, 44208, 29073, 20925, 64963, 16978, 37625, 47303, 1697, 24841, 35202, 50147, 57860, 50553, 47117, 52385, 40976, 4480, 32828, 48638, 16301, 27989, 5523, 54067, 29243, 15288, 14426, 6751, 7975, 26411, 27531, 2970, 55835, 39462, 59353, 6261, 46369, 24755, 29569, 49595, 14850, 49753, 6151, 50977, 24587, 52097, 26, 6656, 16423, 26623, 49035, 51883, 27161, 55705, 55331, 8736, 8312, 63614, 65374, 24404, 21716, 38095, 20174, 52968, 26902, 5788, 7222, 46638, 44982, 46996, 21941, 46540, 36275, 45804, 11705, 47468, 60834, 25453, 28036, 50323, 4622, 52793, 47126, 55201, 41012, 13696, 16461, 3583, 32530, 37546, 60359, 50788, 25864, 51341, 52255, 7696, 4136, 26687, 32671, 8106, 59947, 27239, 42905, 6282, 18977, 25063, 26498, 49803, 51719, 50713, 6152, 51233, 24607, 57217, 42, 10752, 32870, 59390, 16245, 46421, 5299, 45872, 45498, 48060, 48548, 26029, 28045, 52627, 53779, 4664, 63545, 47198, 40865, 24789, 5505, 49459, 45570, 50105, 47108, 50593, 24589, 52609, 49171, 53761, 56, 14336, 16479, 8191, 48939, 27307, 27545, 6554, 6690, 25127, 26503, 51083, 51723, 51737, 55321, 6176, 57377, 24703, 49025, 49323, 27137, 49561, 6146, 49697, 24583, 51073, 49163, 51713, 49177, 55297]
DIF32 = [3921614603, 2869185418, 1701965273, 2697945252, 2400055106, 3337232445, 1968919797, 3568378804, 2068274951, 4222636058, 4049393784, 963633170, 2787533385, 2053518436, 3744941547, 3698732188, 2469118095, 2261839457, 828686916, 2187822017, 2444802432, 510725251, 482438590, 2809707868, 559241109, 3979689425, 916408910, 1617611030, 2847277713, 3705674555, 85747599, 238690869, 153662638, 37449593, 817337570, 1423790896, 3939782245, 3463036569, 3651553149, 1360891066, 945187152, 2588104376, 3301513240, 1572576279, 2794760220, 3366740324, 1084507, 277633792, 3533467408, 1247989025, 948416987, 1268506040, 3296419370, 4026379799, 4124336556, 2791829462, 1005300580, 699791787, 586724441, 1323461314, 2945550623, 3875709725, 633003044, 353326869, 1137563429, 3172103330, 836803823, 104409281, 625080102, 3995358485, 700650845, 1410613849, 600123237, 1990008883, 485588647, 2540414044, 3506824869, 3722437426, 1057495166, 3719772271, 1473463678, 3942030198, 3971788185, 3135468735, 3647324472, 2459683258, 859155856, 3637557795, 571253835, 3136452802, 3362372664, 3318599771, 1553967590, 2269982701, 2840148149, 601505595, 1770356275, 1821304552, 1967886557, 3296005044, 3785895959, 2470502402, 3991954273, 4089576014, 2945793008, 3819981853, 2162427872, 434402658, 2419969129, 2666042226, 2025654748, 265424905, 3841392223, 3755148599, 943124636, 4208630456, 2658798729, 3928158940, 953485209, 422420408, 1507268201, 3719237080, 1340535422, 2934260718, 2518951148, 2607358036, 3948118761, 1279870056, 258461437, 1361578591, 231771216, 3987884733, 2984781390, 4083162275, 242472688, 1088188846, 2726323377, 3419477920, 1934807880, 3244271762, 3646339874, 2715931578, 2756872115, 89858950, 1233005365, 710229704, 3423292490, 2961996191, 2463349586, 2068268432, 4222273306, 3956004984, 3558069608, 3652289287, 1188689594, 3144566423, 1371250633, 2655328848, 3576966108, 4221780470, 3796710520, 2020611089, 3268402441, 1192737585, 1892662118, 1375935873, 687065411, 1629760168, 3803826784, 2358119441, 1262348334, 1649330218, 2255475571, 2388250692, 2537115852, 2213639845, 44149617, 2859703522, 390787880, 229705671, 2352602557, 4243342382, 3033377967, 3300348054, 603132439, 1084772915, 3601070513, 1648736229, 2366643315, 3502374111, 472510403, 1341833308, 3000459758, 3256035248, 2616001073, 1869735913, 2222852814, 2488828070, 3960833974, 331963327, 2577943299, 568342539, 1482335185, 1442235177, 3299352980, 1015156759, 1502333564, 2171803864, 2333555603, 3415157497, 762284616, 4013591709, 855042988, 511373522, 389889214, 2055115207, 3348293355, 141685764, 1587000200, 2224008207, 1711161766, 795025316, 3900149119, 1718765947, 2908707255, 571139839, 3165703362, 2528414238, 197644884, 3867506843, 2811047125, 3569671829, 247102983, 2306115246, 2750085659, 2762197841, 4095197574, 1613476647, 3905696657, 3721176955, 743199102, 3373124716, 2756833962, 103692934, 844345382, 3139533522, 512219849, 3927386046, 218129817, 1029407677, 2247366285, 464041303, 3609531531, 3779394324, 2139874050, 549293790]
DIF64 = [11063610738641623270, 4889888363054346100, 9956942617708730776, 1444739790535898904, 2677402742647429885, 9167081485467521623, 1498787857641651615, 16525036704258760189, 10938053669346010081, 2333518683637448659, 6607515133698341705, 6611275873201017421, 6258764361245447757, 3938161662922734816, 15624529436305723, 3999879535694265088, 13234734986166048702, 8754622446711244954, 1801667130362727051, 3261810259536864080, 8771478623799022308, 15935741287322285195, 7124963015864404861, 2142986349550282324, 7848371670970394059, 4026655318618982387, 15297507576046970046, 17761138668034084171, 5720172745174496141, 11715572599769928880, 18382371086511676130, 14989147811855739323, 5042874578792550864, 16640992886573025164, 1615968848647860203, 17576932069003676274, 12700946151396625811, 5273393168426909963, 11893237161226201252, 13688203791226825331, 17988754664561560486, 2652214229877462959, 821337956778860242, 3064118979356803769, 7036947907449102197, 8123084928293049182, 2684807734222388669, 1543036158982574679, 15184095000251288440, 5623133517676802399, 6561276586347911221, 16678433756597628493, 119418295427756142, 4222935802620833925, 12338293918640240659, 12353955660336499412, 16361537329904111060, 9785106493114069237, 17696161205067198645, 9478426951667347591, 5193703638769212206, 771029817772004129, 7969204530730217276, 17564394052401501052, 11299268343355491219, 7766551211277589866, 14774833320725709410, 11140858694662060315, 8358025652621176702, 5161613427741548727, 848639390616879875, 9909728239579141049, 11095246111816133394, 3472428494000511860, 15922271173611259695, 2332121304990839288, 7258542088211746889, 985822713183987776, 12269316801138436781, 5087076061667404369, 11551450750447745926, 10420986585813978989, 12454013224169805634, 11326547673778077509, 1872180738034914799, 15481269950218504016, 15148742270981865668, 14812413315614788959, 8926190641890331, 2285104804323924736, 15040607117163795012, 18096900801308716752, 1322111154576835104, 4314606191698598121, 4867272343691430550, 15742276316707158936, 16984839992979078380, 6096715355173233990, 13958219519931651183, 12904803386712490035, 4134006227860413441, 5375694091178295577, 3758944970380199854, 4180414894446478516, 3605944487087294739, 5906051574245540768, 13981039557973489009, 2704860401895252793, 16045106884417672791, 14689154461983189623, 99726487065138703, 17335508386063061381, 17015758148974905241, 2268099165261673687, 2233893788020720964, 7388962851422787140, 10060103918979106511, 3771105168868966045, 5034868365743962036, 14006479168290333580, 4767736526403165753, 17207716948511902237, 4763295110187684696, 16012162791654304541, 6255735584697311351, 4460939849756837600, 4761962909661570, 1219062504873361920, 4568491393067473766, 4144020361176308749, 10875664975567342873, 10907873886545811798, 10027844153670944979, 9435531906639520413, 11625552240628080555, 1944162393175604456, 17525416771824205146, 7729856344633337235, 4659125492602829666, 15801171077577716370, 5164342134317951081, 78573873277656323, 9655201204150672773, 8608701453087499066, 4487452175383788844, 10047924895604410504, 15679539739740649885, 2387379515291829478, 9986124203204432076, 12677980915399058200, 11252761003155904591, 10164174802643796330, 17148304033508565385, 5962498326373874258, 12554277990165674619, 14270869710981473738, 15236757892511449506, 1709866432049919450, 13153905605933983223, 14740325771094449951, 10568901444272134814, 2968912036990240717, 17457960095034365567, 9833291793617018390, 18127280255459007127, 11982716523725063456, 16008613413090186105, 5365189811816563831, 15752618329690712494, 67635844509305580, 17314776194382228480, 3624320683420811929, 1673528107878926752, 3870430586712268791, 3758230009969001265, 4007378911019703220, 12166444413320176574, 7154819574910622430, 2636760499989715921, 5930260608922755282, 6751450889620224635, 1421331517354318425, 5312078562288942956, 3719180846543048612, 6116464454910765605, 13284454580495349615, 4246571514053169336, 16069295415807821075, 17524151414581326066, 8054293711739604371, 4597565159405036281, 10582637021310731021, 6368126180305327309, 12444469219757812551, 18088182655038110277, 3557908282795808544, 2206201596680392106, 7651695992245987009, 12092081579694995431, 14442968822706572028, 10463170075648827397, 10691700785551106503, 12581904204310537433, 7217642019075655626, 11249118982357150528, 13276322725271195242, 6902603848521061816, 16127694602424908502, 2575366882219046386, 11663104315853989699, 10885959778180224232, 17948308201527408339, 10743537923390988975, 4933885156862792284, 17826900122381931785, 14148124371610857224, 3492088850348417069, 11103724593485045295, 17861532025810410366, 4715189411747665928, 10281608731437254167, 7616104568198685059, 279465218211891437, 14226164192977932298, 10947715559125400744, 413982539996018387, 14992781978897650718, 5823894437246973136, 8430089059976141812, 11387059262370418214, 1533198612887702501, 18179773874854099320, 11921142446609895089, 13895169852539993971, 4741817623017456310, 3407628723376486423, 13889135207257241195, 6079837965963336374, 413121771626882159, 15377520067784747038, 5252185327260595150, 18053933598135825185, 3021400412007804325, 3448996564484079231, 6329879699802955371, 12080497481307391077, 11626023698389272828, 1970275041005333480, 14785799433083167711, 11667391723826758683, 11988532400301542632, 14614610554166352761, 10979799613095544458, 4091022007653359089, 4650238986488819612, 18102010278767414418]

org16, org32, org64 = 42033, 3196829087, 5603638264384376033

def parser(L):
    val1 = int(L.split(b" ")[7][1:-1].decode(), 16)
    val2 = int(L.split(b" ")[8][:-1].decode(), 16)
    val3 = int(L.split(b" ")[9][:-3].decode(), 16)
    return val1, val2, val3

def parser2(L):
    val1 = int(L.split(b" ")[8][1:-1].decode(), 16)
    val2 = int(L.split(b" ")[9][:-1].decode(), 16)
    val3 = int(L.split(b" ")[10][:-3].decode(), 16)
    return val1, val2, val3

def get_res(S):
    r = remote('story.2021.ctfcompetition.com', 1337)
    for _ in range(2):
        r.recvline()
    r.sendline(S)
    v16, v32, v64 = parser(r.recvline())
    r.close()
    return v16, v32, v64

r = remote('story.2021.ctfcompetition.com', 1337)
for _ in range(2):
    r.recvline()
r.sendline(b"a" * 256)

v16, v32, v64 = parser(r.recvline())
tar16, tar32, tar64 = parser2(r.recvline())

M = Matrix(GF(2), 112, 256)
dif = [0] * 112
for i in range(16):
    for j in range(256):
        M[i, j] = (DIF16[j] >> i) & 1
    dif[i] = ((tar16 ^ v16) >> i) & 1
for i in range(32):
    for j in range(256):
        M[i + 16, j] = (DIF32[j] >> i) & 1
    dif[i + 16] = ((tar32 ^ v32) >> i) & 1
for i in range(64):
    for j in range(256):
        M[i + 48, j] = (DIF64[j] >> i) & 1
    dif[i + 48] = ((tar64 ^ v64) >> i) & 1

dif = vector(GF(2), dif)
res = M.solve_right(dif)

fin = b''
for i in range(256):
    if int(res[i]) == 0:
        fin += b"a"
    else:
        fin += b"A"

r.sendline(fin)
print(r.recvline())
print(r.recvline())

'''
quer = b''
val16, val32, val64 = org16, org32, org64
for i in range(256):
    bt = rand.randint(0, 1)
    if bt == 0:
        quer += b"a"
    if bt == 1:
        quer += b"A"
        val16 ^= DIF16[i]
        val32 ^= DIF32[i]
        val64 ^= DIF64[i]

print(quer)
print(get_res(quer))
print(val16, val32, val64)
'''

'''
r = remote('story.2021.ctfcompetition.com', 1337)
for _ in range(2):
    r.recvline()

S = b"a" * 256
r.sendline(b"a" * 256)
org16, org32, org64 = parser(r.recvline())
r.close()

print(org16, org32, org64)


for i in tqdm(range(256)):
    r = remote('story.2021.ctfcompetition.com', 1337)
    for _ in range(2):
        r.recvline()
    ex = b"a" * i + b"A" + b"a" * (255 - i)
    r.sendline(ex)
    new16, new32, new64 = parser(r.recvline())
    DIF16.append(new16 ^ org16)
    DIF32.append(new32 ^ org32)
    DIF64.append(new64 ^ org64)
    r.close()

print(DIF16)
print(DIF32)
print(DIF64)
'''