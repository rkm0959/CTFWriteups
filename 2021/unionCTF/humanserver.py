# curve parameter
X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
# random nonce
nonce = 0x7918768917649876918679818976981769817691968917698769
 
r = remote('134.122.111.232', 54321)
r.recvuntil("Alice sends public key")
r.recvline()
r.recvline()
r.recvline()
 
AliceKey = json.loads(r.recvline())
AX = AliceKey["Px"]
AY = AliceKey["Py"]
 
r.recvuntil("Please forward Alice's key to Bob")
r.recvline()
r.recvline()
r.recvline()
 
data = {
    "Px" : X,
    "Py" : Y,
    "nonce" : nonce
}
 
r.send(json.dumps(data))
 
r.recvuntil("Bob sends public key")
r.recvline()
r.recvline()
r.recvline()
 
BobKey = json.loads(r.recvline())
BX = BobKey["Px"]
BY = BobKey["Py"]
 
r.recvuntil("Please forward Bob's key to Alice")
r.recvline()
r.recvline()
r.recvline()
 
 
nonce2 = nonce ^ AX ^ BX
 
data = {
    "Px" : X,
    "Py" : Y,
    "nonce" : nonce2
}
 
r.send(json.dumps(data))
 
shared_secret = BX ^ nonce
 
r.recvuntil("Alice sends encrypted flag to Bob")
r.recvline()
r.recvline()
r.recvline()
 
fin = json.loads(r.recvline())
 
iv = bytes.fromhex(fin["iv"])
enc = bytes.fromhex(fin["encrypted_flag"])
 
key = hashlib.sha1(long_to_bytes(shared_secret)).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(enc)
 
print(flag)
