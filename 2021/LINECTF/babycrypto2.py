def bytexor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))
 
r = remote('35.200.39.68', '16002')
 
def get_data():
    t = r.recvline()
    t = t.rstrip(b"\n")
    t = t.split()[-1]
    return t
 
 
inp = b64decode(get_data())
IV = inp[:16]
CTXT = inp[16:]
 
 
print(r.recv(1024))
 
IV = bytexor(IV, pad(b"Command: test", 16))
IV = bytexor(IV, pad(b"Command: show", 16))
 
vv = IV + CTXT
vv = b64encode(vv)
 
r.sendline(vv)
print(r.recv(1024))
 
print(r.recv(1024))