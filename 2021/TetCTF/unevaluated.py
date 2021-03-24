Complex = namedtuple("Complex", ["re", "im"])
 
 
def complex_mult(c1, c2, modulus):
    return Complex(
        (c1.re * c2.re - c1.im * c2.im) % modulus,  # real part
        (c1.re * c2.im + c1.im * c2.re) % modulus,  # image part
    )
 
 
def complex_pow(c, exp, modulus):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = complex_mult(result, c, modulus)
        c = complex_mult(c, c, modulus)
        exp >>= 1
    return result

def norm(x):
    return x.re * x.re + x.im * x.im
 
 
g = Complex(re=20878314020629522511110696411629430299663617500650083274468525283663940214962,
            im=16739915489749335460111660035712237713219278122190661324570170645550234520364)
order = 364822540633315669941067187619936391080373745485429146147669403317263780363306505857156064209602926535333071909491
n = 42481052689091692859661163257336968116308378645346086679008747728668973847769
public_key = Complex(re=11048898386036746197306883207419421777457078734258168057000593553461884996107,
                     im=34230477038891719323025391618998268890391645779869016241994899690290519616973)
encrypted_flag = b'\'{\xda\xec\xe9\xa4\xc1b\x96\x9a\x8b\x92\x85\xb6&p\xe6W\x8axC)\xa7\x0f(N\xa1\x0b\x05\x19@<T>L9!\xb7\x9e3\xbc\x99\xf0\x8f\xb3\xacZ:\xb3\x1c\xb9\xb7;\xc7\x8a:\xb7\x10\xbd\x07"\xad\xc5\x84'
 
p = 206109322179011817882783419945552366363
q = 17175776848250984823565284995462697197
r = 103054661089505908941391709972776183181
 
# solve for mod p
p_g = complex_pow(g, q * r, n)
p_enc = complex_pow(public_key, q * r, n)
 
# norm : a^2 + b^2
c_1 = norm(p_g) % (p * p)
c_2 = norm(p_enc) % (p * p)
 
c_1 = (c_1 - 1) // p
c_2 = (c_2 - 1) // p
 
val_p = (c_2 * inverse(c_1, p)) % p 
 
# solve for mod r
r_g = complex_pow(g, p * q, n)
r_enc = complex_pow(public_key, p * q, n)
print(norm(r_g) % p, norm(r_enc) % p)
 
'''
p = 206109322179011817882783419945552366363
g = GF(p)(176015758946526802279559144270141551487) # r_g
enc = GF(p)(28369875517706698292997652748535456248) # r_enc
print(g.multiplicative_order()) # this equals r
print(enc.log(g)) # 26176203815975575469683683780455489251
'''
 
val_r = 26176203815975575469683683780455489251
val_tot, pr = CRT(val_p, p, val_r, r)
 
for i in range(0, 100):
    private_key = long_to_bytes(val_tot + i * pr)
    flag = AES.new(private_key, AES.MODE_ECB).decrypt(encrypted_flag)
    if b"TetCTF" in flag:
        print(flag)
        break