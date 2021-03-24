cc = 'Here is the ciphertext for some message you might like to read: '
print(conn.recvline())
T = conn.recvline()
print(T)
hxval = T[len(cc):-1]
hxval = hxval.decode()
print(len(hxval))
conn.send((b'\x10' * 16).hex() + "\n")
T = conn.recvline()
cc = "Enter plaintext to encrypt (hex): "
print(T)
IV = T[len(cc):-1]
print(IV)
IV = IV.decode()
IV = bytes.fromhex(IV)
IV = IV[-16:]
## change indexes to find different blocks (below)
conn.send((strxor(bytes.fromhex(hxval[160:192]), strxor(bytes.fromhex(hxval[128:160]), IV))).hex() + "\n") 
print(conn.recvline()) ## change hex -> bytes here
