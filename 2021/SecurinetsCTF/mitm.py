# repeatedly send -1

g = 2
p = 0xf18d09115c60ea0e71137b1b35810d0c774f98faae5abcfa98d2e2924715278da4f2738fc5e3d077546373484585288f0637796f52b7584f9158e0f86557b320fe71558251c852e0992eb42028b9117adffa461d25c8ce5b949957abd2a217a011e2986f93e1aadb8c31e8fa787d2710683676f8be5eca76b1badba33f601f45        
        
C = '45b18b204d78c392f644786f700577d1644340dd37cd31cfe58bdd5cf6858c26ef3cf3d2f6a9f797b5d66d859a109bb337ed6ff89fd08fed281a131986e2b0acda4fc53f343088622f8a1d237443c93a279800c55fc1f026238b0482f4bd3554'
iv = bytes.fromhex(C[:32])
ct = bytes.fromhex(C[32:])

key1 = hashlib.sha1(long_to_bytes(1)).digest()[:16]
key2 = hashlib.sha1(long_to_bytes(pow(2, (p-1)//2, p))).digest()[:16]

p1 = AES.new(key1, AES.MODE_CBC, iv).decrypt(ct)
p2 = AES.new(key2, AES.MODE_CBC, iv).decrypt(ct)

print(p1)
print(p2)