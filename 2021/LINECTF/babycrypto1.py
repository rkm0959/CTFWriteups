def bytexor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))
 
r = remote('35.200.115.41', '16001')
 
def get_data():
    t = r.recvline()
    print(t)
    t = t.rstrip(b"\n")
    t = t.split()[-1]
    if t[:11] == b"Ciphertext:":
        t = t[11:]
    print(t)
    return t
 
 
inp = b64decode(get_data())
IV = inp[:16]
CTXT = inp[16:]
 
print(CTXT)
print(r.recvline())
 
print(r.recv(1024))
 
ss = b64encode(b"\x00" * 16)
r.sendline(ss)
 
print(r.recv(1024))
 
val = bytexor(pad(b'show', 16), CTXT[9*16:10*16])
val = b64encode(val)
r.sendline(val)
 
cc = b64decode(get_data())
cc = cc[16:32]
 
print(len(cc))
vv = IV + CTXT[:160] + cc
 
vv = b64encode(vv)
 
print(r.recv(1024))
 
r.sendline(vv)
 
print(r.recv(1024))