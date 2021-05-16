from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
import multiprocessing as mp


freq = [8.2, 1.5, 2.8, 4.3, 13, 2.2, 2, 6.1, 7, 0.15, 0.77, 4, 2.4, 6.7, 7.5, 1.9, 0.095, 6, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2, 0.074]

def ev(words, idx, sft):
    res = 0
    for word in words:
        if len(word) <= idx:
            continue
        cc = (ord(word[idx]) - ord('a') + sft) % 26
        res += freq[cc]
    return res
    
res = 'pm vuh bzhu h rlb aodv pz ayxnd yhqftp pz ha slduy hz svqi hz aoh luftdssuw tlvufjd hug pz bzhf vuoa vufg aoh cpjgshqu jpsjju pz aohqwhsyvbwcj buetjdjqump ovzgahq pu aodv jhvg aoh rlb uvw aoh jpsjju wyrxngdi jybryrfhtqszn zaugsjsx hug zbfj zfvvjpr hyh wyrrjuko yligwudt av jvonjfsyofwp hz vuhvnpd whg zfvvjpr pyugxsdsmjgv vm aoh jpsjjur ltsntbdt jvqhjgdhtup jpsjju dohgq jhsvzudt ha aoh zbutjqcuk vm tvekqh hsddfpz pu thb uhwktqzb jybryrkezjn tbvgzp cpjgshqu hjwwfoko puygswdt h zauqsjdh jpsjju hu hbwqphx jpsjju aoh uhpg cpjgshqu jpsjju ilfcrh hzvqhlzjxe dpwj h zpprqhq wvoafooxtcpktm jpsjju puvvjdc pu mhfv aoh adr jpsjjur dlug vmwgs jvqhzvdt hug ivwj dlug zvpgyllul jhonjg sl jolhkud pugghkhvyslswo ihedfjd hjwwfoko iyrmj aoh tbfjxwqeghpi hbwqphx jpsjju ibw rhvkxnh pz nlqgwdkbr jyhfnwdt dpwj aoh mpuuy wbennvguw zvowylnd av aoh mpagindo wvoafooxtcpktm jpsjjur h zpprqh chukfqs pz av luftdss if bzlpl aoh cpjgshqu klftdssyho tlwjtg hug av klftdss if bzlpl cpjgshqu luftdssyho aodv tlwjtg pz zvpgyllul yligwudt av hz chukfqs ildwkrqj pa pz kpihjuddm myro aoh ildwkrqj jpsjju jyhcyhc if mydphlr ildwkrqj dolem pz zppkqdq av cpjgshqu ibw bzhu h zslimwko tvgkkldt lufkukdhbor tlfjfqhif hug ahenjdt aoh ildwkrqj jpsjju pz h ylfkuunstm jpsjju klvrnwd aoh cpjgshqu jpsjjur hwscwhmj zaugsjsx pa ulygw ilfcrh dpggqb bzhf aouqzjgenu lbuquh aoh nyrpxidbw jpsjju pz h chukfqs jyhcyhc if jvxpy nyrpxidbw qvvuj thakrlkqto chq nyrpxydbw ul chq iyrphngekte pa pz pkhpylbqe av aoh cpjgshqu jpsjju lefguw aodv pa bzhu qbvv kpihjuddm jpsjju hssjfedjl jvutjvoegeter av aoh kpjkyv av h nyrpxidbw rlb vm pz aoh zhpg hz h cpjgshqu rlb vm hiff aoh nyrpxidbw jpsjju pz zaugsjsxxopu ilfczvd pav rlb pz uvw h dvuf ibw pa pz dldmjqdt ilfczvd pa ohv qbvv jpsjju hssjfedjl pa pz nyrpxidbwt jpsjju aodv ilfcrh dpggqb bzhf aouqzjgenu nluofqx hug lbuquh klvrnwd pav dldmshrixt aoh msdi pz msdv jbund iydej uvwutsdhyfnk wvoafooxtcpktm zohpfqhwtod jbund iydej'

words = res.split()

ans = [0] * 14
for i in range(14):
    idx = 0
    val = 0
    for j in range(26):
        tt = ev(words, i, j)
        if tt > val:
            val = tt
            idx = j
    ans[i] = idx

# patches

ans[0] += (ord('i') - ord('t') + 26) % 26
ans[0] %= 26

ans[12] += (ord('g') - ord('c') + 26) % 26
ans[12] %= 26

for word in words:
    fin = ''
    for i, c in enumerate(word):
        cc = chr(ord('a') + (ord(c) - ord('a') + ans[i]) % 26)
        fin += cc 
    print(fin)
