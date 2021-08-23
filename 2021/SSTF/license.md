# License Writeup

## Step 1 
We reverse engineer the given file. This was the result.

```py
import binascii
import hashlib

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def base32_decode(x):
    B = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    b = ""
    for i in x:
        b += "{0:05b}".format(B.find(i))
    return int_to_bytes(int(b, 2))

k1 = base32_decode("BHAWBGQ5-MB4IUR5V-26YFXZSW-MSHEVTDN-GZB4ED2N-KDHX7A5I".replace("-", ""))
# k1 = base32_decode("BJUWBPYH-MCVFRYIZ-ZV45N5EU-D5HL6K6H-6N4VCS6X-BIUQSUTR".replace("-", ""))

assert(k1[0] ^ k1[7] == k1[28] and k1[1] ^ k1[3] == k1[12])

buf = b""

# just encode hex
B = b"0123456789ABCDEF"
for i in k1[6:]:
    buf += bytes([B[i >> 4]])
    buf += bytes([B[i & 0xF]])

key = EC_KEY_new_by_curve_name(409)
x = 4910017285067243285659645658183706496882752243738091681795
y = 894613538273475752824630788065081050497548342550540448591
EC_KEY_set_public_key_affine_coordinates(key, x, y)

sig = ECDSA_SIG_new()

r = 5241427081939067204984227503904086701023032271828334909509
s = int(buf, 16)

ECDSA_SIG_set0(sig, r, s)
dgst = hashlib.sha1(bytes(k1[:6])).digest()
ret = ECDSA_do_verify(dgst, 20, sig, key)

assert(ret == 1)

# unix time
expir_time = (k1[2] << 24) | (k1[3] << 16) | (k1[4] << 8) | k1[5]

# compare with current time
if not_expir(expir_time):
    hsh = hashlib.sha256(k1[:30]).digest()
    xor = [0x9C, 0xA2, 0x53, 0xC7, 0xC9, 0xBA, 0xA7, 0x7A, 0x2F, 0x93, 0xE5, 0xB1, 0xC2, 0xAD, 0xE8, 0x01, 0x0F, 0x2B, 0xE4, 0x5F, 0x9E, 0xCA, 0xA8, 0x9A, 0xA4, 0xAB, 0xC9, 0x53, 0x58, 0x30, 0xF2, 0x95]
    ans = []
    for i in range(32):
        ans.append(hsh[i] ^ xor[i])
    print(bytes(ans))
```

## Step 2 
We make the code self contained. Some notes here - 
  
  - curve name 409 corresponds to SECP192R1
  - the other ECDSA functions have trivial meanings 

Now we can fix the code to 

```py
p = (1 << 192) - (1 << 64) - 1
a = p - 3
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1

E = EllipticCurve(GF(p), [a, b])
n = E.order()

Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def base32_decode(x):
    B = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    b = ""
    for i in x:
        b += "{0:05b}".format(B.find(i))
    return int_to_bytes(int(b, 2))

def verify(dgst, sig, PK):
    z = bytes_to_long(dgst)
    r, s = sig
    u_1 = (z * inverse(s, n)) % n
    u_2 = (r * inverse(s, n)) % n
    GG = u_1 * E(Gx, Gy) + u_2 * PK
    cc = int(GG.xy()[0])
    assert cc == r


k1 = base32_decode("BHAWBGQ5-MB4IUR5V-26YFXZSW-MSHEVTDN-GZB4ED2N-KDHX7A5I".replace("-", ""))
k1 = base32_decode("BJUWBPYH-MCVFRYIZ-ZV45N5EU-D5HL6K6H-6N4VCS6X-BIUQSUTR".replace("-", ""))

assert(k1[0] ^ k1[7] == k1[28] and k1[1] ^ k1[3] == k1[12])

print(k1)

buf = b""
B = b"0123456789ABCDEF"
for i in k1[6:]:
    buf += bytes([B[i >> 4]])
    buf += bytes([B[i & 0xF]])


x = 4910017285067243285659645658183706496882752243738091681795
y = 894613538273475752824630788065081050497548342550540448591
PK = E(x, y)

r = 5241427081939067204984227503904086701023032271828334909509
s = int(buf, 16)

dgst = hashlib.sha1(bytes(k1[:6])).digest()
verify(dgst, (r, s), PK)

expir_time = (k1[2] << 24) | (k1[3] << 16) | (k1[4] << 8) | k1[5]


if expir_time > 1629123226:
    hsh = hashlib.sha256(k1[:30]).digest()
    xor = [0x9C, 0xA2, 0x53, 0xC7, 0xC9, 0xBA, 0xA7, 0x7A, 0x2F, 0x93, 0xE5, 0xB1, 0xC2, 0xAD, 0xE8, 0x01, 0x0F, 0x2B, 0xE4, 0x5F, 0x9E, 0xCA, 0xA8, 0x9A, 0xA4, 0xAB, 0xC9, 0x53, 0x58, 0x30, 0xF2, 0x95]
    ans = []
    for i in range(32):
        ans.append(hsh[i] ^ xor[i])
    print(bytes(ans))
```

## Step 3 
We do some elliptic curve cryptography. 

The key issue here is that the signature has fixed $r$. 

Consider a signature along with the hash and public key $(z, r, s, Q)$. 

The verification algorithm lets $u_1 = zs^{-1}$, $u_2 = rs^{-1}$ and checks if $u_1 G + u_2 Q$ has $x$ coordinate $r$. 

Here, the modular inverse is taken $\pmod{n}$, where $n$ is the elliptic curve order. 

Since $r$ is same for both license keys, $u_1 G + u_2 Q$ is the same (or is additive inverse of another) for the two license keys. 

Since we know all of $z, r, s, Q$ for both license keys, we can recover the private key here. 

Indeed, if we let the first set $(z_1, r, s_1, Q)$ and the second set $(z_2, r, s_2, Q)$, we see that $(z_1/s_1) G + (r/s_1) Q = (z_2/s_2) G + (r/s_2) Q$.

We can solve this equation to get $Q = dG$ for some $d$ which we can now compute fast. 

Of course, there is a chance that the two points in the equation mentioned before are additive inverses of each other.

However, it turns out the the equality holds in this case. In conclusion, we can find the private key $d$ for the public key. 

With the private key in hand, we can compute $s$ such that $(z, r, s, Q)$ is a valid signature for any $z$. 

```py
p = (1 << 192) - (1 << 64) - 1
a = p - 3
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1

E = EllipticCurve(GF(p), [a, b])
n = E.order()

Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

G = E(Gx, Gy)

x = 4910017285067243285659645658183706496882752243738091681795
y = 894613538273475752824630788065081050497548342550540448591
PK = E(x, y)

# these are z/s, r/s values from the two keys
u11, u12 = 6208018712665992685317371884848654579228254089530446391244, 3901371225190145511686010375115837075071144129982529625516
u21, u22 = 2861418786602039821386694068852808988532492969716540836428, 5623577365242345842961574633168820564776518525420727533800

target = 4295308421698895742407195884872675142566054683881561619252
dlog = 1325031087835349138965290766193329882829064869944584756462

r = 5241427081939067204984227503904086701023032271828334909509

assert u11 * G + u12 * PK == u21 * G + u22 * PK 
# we solve this to find PK = ? * G 
# PK = (u11 - u21) / (u22 - u12) G
assert PK == dlog * G
# now note that u_11 * G + u_12 * PK = (u_11 + u_12 * dlog) * G has x coordinate r
# therefore, we set target = u_11 + u_12 * dlog = u_21 + u_22 * dlog (mod n)
assert int((target * G).xy()[0]) == r
```

## Step 4

Now we aim to finish the problem. If we fix the first 6 bytes of k1, we can find $z$ and use it to compute $s$. 

Therefore, we want to brute force the first 6 bytes, which is quite infeasible. We decrease the amount of brute force by...

Guessing! We guess that the expiration time is larger than the current time (as of the competition) and is a multiple of 3600.

This can be inferred by the fact that the two expiration time from the two keys are also a multiple of 3600. 

Also, it's reasonable that the expiration time for a license key will be in a form of X o'clock. 

We now try all expiration time that is larger than the current unix time and is a multiple of 3600. 

For a fixed expiration time, there is 2 bytes of freedom from the first two bytes of k1.

We brute force 16 bits, compute $s$, then check if all conditions (byte XOR) hold. Eventually, this finds the flag.

```py
p = (1 << 192) - (1 << 64) - 1
a = p - 3
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1

E = EllipticCurve(GF(p), [a, b])
n = E.order()

Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

G = E(Gx, Gy)

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def base32_decode(x):
    B = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    b = ""
    for i in x:
        b += "{0:05b}".format(B.find(i))
    return int_to_bytes(int(b, 2))

def verify(dgst, sig, PK):
    z = bytes_to_long(dgst)
    r, s = sig
    u_1 = (z * inverse(s, n)) % n
    u_2 = (r * inverse(s, n)) % n
    # print(u_1, u_2)
    GG = u_1 * G + u_2 * PK
    cc = int(GG.xy()[0])
    assert cc == r

x = 4910017285067243285659645658183706496882752243738091681795
y = 894613538273475752824630788065081050497548342550540448591
PK = E(x, y)
target = 4295308421698895742407195884872675142566054683881561619252
dlog = 1325031087835349138965290766193329882829064869944584756462

r = 5241427081939067204984227503904086701023032271828334909509

assert u11 * G + u12 * PK == u21 * G + u22 * PK
assert PK == dlog * G
assert int((target * G).xy()[0]) == r

trial = 0
tsp = 1629129600
iv = inverse(target, n)
rdlog = (r * dlog) % n 
cnt = 0

while True:
    tsp += 3600
    for i in range(256):
        for j in range(256):
            k1 = bytes([i]) + bytes([j]) + long_to_bytes(tsp)
            dgst = hashlib.sha1(bytes(k1[:6])).digest()

            s = ((bytes_to_long(dgst) + rdlog) * iv) % n 
            s_bytes = long_to_bytes(s, blocksize = 24)
            k1 += s_bytes

            if k1[0] ^ k1[7] != k1[28] or k1[1] ^ k1[3] != k1[12]:
                continue
          
            hsh = hashlib.sha256(k1[:30]).digest()
            xor = [0x9C, 0xA2, 0x53, 0xC7, 0xC9, 0xBA, 0xA7, 0x7A, 0x2F, 0x93, 0xE5, 0xB1, 0xC2, 0xAD, 0xE8, 0x01, 0x0F, 0x2B, 0xE4, 0x5F, 0x9E, 0xCA, 0xA8, 0x9A, 0xA4, 0xAB, 0xC9, 0x53, 0x58, 0x30, 0xF2, 0x95]
            ans = []
            for i in range(32):
                ans.append(hsh[i] ^ xor[i])
            ans = bytes(ans)
            if ans[:4] == b"SCTF":
                print(ans)
```

flag : ``SCTF{3ll1p71c_k3y5_4r3_5m4ll3r!}``
