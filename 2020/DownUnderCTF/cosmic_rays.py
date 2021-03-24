## part 1 : brute force to find the key and final 32 bytes of output
def solve(KEY):
    msg = 'If Bruce Schneier multiplies two primes, the product is prime. On a completely unrelated note, the key used to encrypt this message is ' + KEY
    msg = msg.encode()
    msg = pad(msg, 16)
    CV = ctxt[-32:]
    for i in range(0, 16):
        for j in range(0, 16):
            CVV = CV[0:4] + cc[i] + CV[5:18] + cc[j] + CV[19:]
            c_n = bytes.fromhex(CVV)
            c_n_1 = AES.new(bytes.fromhex(KEY), AES.MODE_ECB).decrypt(strxor(c_n, msg[-32:-16]))
            c_n_1 = strxor(c_n_1, msg[-16:])
            c_n_1 = strxor(c_n_1, msg[-48:-32])
            found_c = False
            tt = c_n_1.hex()
            for k in range(0, 32):
                if ctxt[-64+k] != '▒' and ctxt[-64+k] != tt[k]:
                    found_c = True
                    break
            if found_c == False:
                print("found!", KEY, i, j)
 
for i in range(0, 16):
    for j in range(0, 16):
        for k in range(0, 16):
            KEY = key0 + cc[i] + key1 + cc[j] + key2 + cc[k] + key3
            solve(KEY)
 
## part 2 : recover entire output
KEY = '0b9d0fe1920ca685e3851b162b8cc9e5'
## change the final 32 hex data of 'ciphertext' accordingly 
 
for i in range(1, 10):
    if i == 1:
        CVV = ctxt[-32*i : ]
    else:
        CVV = ctxt[-32*i : -32*(i-1)]
    c_n = bytes.fromhex(CVV)
    print(len(c_n))
    print(len(msg[-16*(i+1):-16*i]))
    c_n_1 = AES.new(bytes.fromhex(KEY), AES.MODE_ECB).decrypt(strxor(c_n, msg[-16*(i+1):-16*i]))
    if i == 1:
        c_n_1 = strxor(c_n_1, msg[-16*i:])
    else:
        c_n_1 = strxor(c_n_1, msg[-16*i:-16*(i-1)])
    c_n_1 = strxor(c_n_1, msg[-16*(i+2):-16*(i+1)])
    ctxt = ctxt[0:-32*(i+1)] + c_n_1.hex() + ctxt[-32*i:]
 
## part 3 : recover answer
ctxt = 'ed5dd65ef5ac36e886830cf006359b300112c744b0aac58207aea28e804ec6abd6e5c397d1d4bd6f42539db06aff5de0a45d08c7dee9da217412bb6edcdab75f3096f135f702fdda23b764c1bfde3b103a1fe35ed6c0b03d2e1a8badb6c04e330c0dff963317506a110a742feea43cf2ed1e8e0f0f5e33993c8ee28200461ad755fca0ebd654e6962862f31270f414eab7c9076140feb15c1e690a83a0e60d75975d21cde66e41791b8780988c9b8329'
c_2 = strxor(bytes.fromhex(ctxt[32:64]), msg[0:16])
c_1 = strxor(AES.new(bytes.fromhex(KEY), AES.MODE_ECB).decrypt(c_2), msg[16:32])
c_0 = strxor(AES.new(bytes.fromhex(KEY), AES.MODE_ECB).decrypt(c_1), msg[0:16])
p_0 = strxor(bytes.fromhex(ctxt[0:32]), c_1)
print(c_0 + p_0)
