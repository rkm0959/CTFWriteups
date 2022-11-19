from sage.all import * 
from Crypto.Util.number import * 
from tqdm import tqdm 

flag_enc = 12511151067854980018402338064249011501289483981739622405966873800434582787927582776701500428569583627075942209200111820852675630661710277645689222093776809
e = 65537
N = 26490549988428481763168213014112595006292202094401331709249114650866758994292273319027195690444828086778317053421852576699960985597838153195793962326613257

assert flag_enc < N

g = 2

for i in tqdm(range(2, 1 << 12)):
    if isPrime(i):
        for j in range(5):
            g = pow(g, i, N)
        p = GCD(g - 1, N)
        if p != 1 and p != N:
            q = N // p
            phi = (p - 1) * (q - 1)
            d = inverse(65537, phi)
            print(long_to_bytes(pow(flag_enc, d, N)))
