from qulacs import QuantumCircuit, QuantumState
from qulacs.gate import *
import random
from pwn import *
from Crypto.Cipher import AES
import base64
 
 
# CNOT gate
def ADD_CNOT(a, b):
    return "CNOT " + str(a) + "," + str(b) + "; "
 
# single qubit gates
def ADD_single(s, a):
    return s + " " + str(a) + "; "
 
# toffoli
def ADD_toffoli(a, b, c): 
    ret = ""
    ret += ADD_single("H", c)
    ret += ADD_CNOT(b, c)
 
    ret += ADD_single("TDAG", c)
    ret += ADD_CNOT(a, c)
 
    ret += ADD_single("T", c)
    ret += ADD_CNOT(b, c)
 
    ret += ADD_single("TDAG", c)
    ret += ADD_CNOT(a, c)
 
    ret += ADD_single("T", b)
    ret += ADD_single("T", c)
 
    ret += ADD_CNOT(a, b)
    ret += ADD_single("H", c)
 
    ret += ADD_single("T", a)
    ret += ADD_single("TDAG", b)
 
    ret += ADD_CNOT(a, b)
 
    return ret 
 
 
 
N = 128
xi, xip = 0.98, 0.98
p = (xi * (1 + xi))**0.5 - xi
Np = int(N * (1 + 2*xi + 2*(xi*(1+xi))**0.5 + xip))
 
# shor error correction
decoder = ""
decoder += ADD_CNOT(0, 1)
decoder += ADD_CNOT(3, 4)
decoder += ADD_CNOT(6, 7)
decoder += ADD_CNOT(0, 2)
decoder += ADD_CNOT(3, 5)
decoder += ADD_CNOT(6, 8)
decoder += ADD_toffoli(1, 2, 0)
decoder += ADD_toffoli(4, 5, 3)
decoder += ADD_toffoli(7, 8, 6)
decoder += ADD_single("H", 0)
decoder += ADD_single("H", 3)
decoder += ADD_single("H", 6)
decoder += ADD_CNOT(0, 3)
decoder += ADD_CNOT(0, 6)
decoder += ADD_toffoli(3, 6, 0)
 
r = remote('others.ctf.zer0pts.com', '11099')
 
def get_bin():
    s = r.recvline()
    s = s.split()[-1].decode()
    return int(s, 2)
 
r.recvline()
for i in range(0, 860):
    r.sendline(decoder)
 
measure = get_bin()
bb = (1 << 400) - 1
r.sendline(bin(bb))
 
ba = get_bin()
xa = get_bin()
m = get_bin()
 
l = []
for i in range(Np):
    if (ba >> i) & 1 == (bb >> i) & 1 == 0:
        l.append(i)
 
chosen = []
for i in range(Np):
    if (m & (1 << i)) > 0:
        chosen.append(i)
 
k = 0
for i in sorted(list(set(l) - set(chosen))):
    k = (k << 1) | ((measure >> i) & 1)
 
key = int.to_bytes(k, N // 8, 'big')
s = r.recvline()
vv = s.split()[-1]
 
fin = base64.b64decode(vv)
iv = fin[:16]
ct = fin[16:]
 
cipher = AES.new(key, AES.MODE_CBC, iv)
print(cipher.decrypt(ct))
 