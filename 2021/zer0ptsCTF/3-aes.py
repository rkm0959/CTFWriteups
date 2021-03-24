# get data from server
r = remote('crypto.ctf.zer0pts.com', '10929')
 
def get_enc(ptxt):
    r.recvuntil(b">")
    r.sendline(b"1")
    ptxt = bytes.hex(ptxt)
    r.sendline(ptxt)
    s = r.recvline().split()[-1].rstrip()
    iv1, iv2, ctxt = s.split(b":")
    iv1 = bytes.fromhex(iv1.decode())
    iv2 = bytes.fromhex(iv2.decode())
    ctxt = bytes.fromhex(ctxt.decode())
    return iv1, iv2, ctxt
 
def get_dec(ctxt, iv1, iv2):
    r.recvuntil(b">")
    r.sendline(b"2")
    ctxt = bytes.hex(ctxt)
    iv1 = bytes.hex(iv1)
    iv2 = bytes.hex(iv2)
    goal = iv1 + ":" + iv2 + ":" + ctxt
    r.sendline(goal)
    s = r.recvline()
    print(s)
    s = s.split()[-1].rstrip()
    ptxt = bytes.fromhex(s.decode())
    return ptxt
 
def get_flag():
    r.recvuntil(b">")
    r.sendline(b"3")
    s = r.recvline().split()[-1].rstrip()
    iv1, iv2, ctxt = s.split(b":")
    iv1 = bytes.fromhex(iv1.decode())
    iv2 = bytes.fromhex(iv2.decode())
    ctxt = bytes.fromhex(ctxt.decode())
    assert len(iv1) == 16
    assert len(iv2) == 16
    assert len(ctxt) == 48
    return iv1, iv2, ctxt
 
 
f = open("lol.txt", "w")
ptxt_0 = get_dec(b"\x00" * 16, b"\x00" * 16, b"\x00" * 16)
ptxt_1 = get_dec(b"\x00" * 16, b"\x00" * 15 + b"\x01", b"\x00" * 16)
 
 
f.write(str(bytes_to_long(ptxt_0)) + "\n")
f.write(str(bytes_to_long(ptxt_1)) + "\n")
 
iv1, iv2, ctxt = get_flag()
 
f.write(str(bytes_to_long(iv1)) + "\n")
f.write(str(bytes_to_long(iv2)) + "\n")
f.write(str(bytes_to_long(ctxt)) + "\n")

# find the first key
def bytexor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))
 
for i in tqdm(range(0, 1 << 24)):
    cc = long_to_bytes(i)
    if len(cc) < 3:
        cc = b"\x00" * (3 - len(cc)) + cc
    k1 = hashlib.md5(cc).digest()
    cipher = AES.new(k1, mode = AES.MODE_ECB)
    val_1 = cipher.encrypt(ptxt_0)
    val_2 = cipher.encrypt(ptxt_1)
    det = bytexor(val_1, val_2)
    if bytes_to_long(det) == 1:
        print(i)

# we now know the first key, MITM prep
cipher = AES.new(key = key_1, mode = AES.MODE_ECB)
vv = cipher.encrypt(ptxt_0)
 
f = open("Data1.txt", "w")
for i in tqdm(range(0, 1 << 24)):
    cc = long_to_bytes(i)
    if len(cc) < 3:
        cc = b"\x00" * (3 - len(cc)) + cc
        assert bytes_to_long(cc) == i
    k2 = hashlib.md5(cc).digest()
    cipher = AES.new(key = k2, mode = AES.MODE_ECB)
    res = cipher.encrypt(vv)
    f.write(str(bytes_to_long(res)) + "\n")
 
for i in tqdm(range(0, 1 << 24)):
    cc = long_to_bytes(i)
    if len(cc) < 3:
        cc = b"\x00" * (3 - len(cc)) + cc
    k3 = hashlib.md5(cc).digest()
    cipher = AES.new(key = k3, mode = AES.MODE_ECB)
    res = cipher.encrypt(b"\x00" * 16)
    f.write(str(bytes_to_long(res)) + "\n")
f.close()

# MITM in C++
'''
map<string, int> M;
 
int main(void)
{
    fio; int i, j;
    freopen("Data1.txt", "r", stdin);
    for(i=0 ; i < (1<<24) ;  i++)
    {
        if(i % 1000000 == 0) cout << i / 1000000 << endl;
        string s; cin >> s;
        M[s] = i;
    }
    for(i=0 ; i<(1<<24) ; i++)
    {
        if(i % 1000000 == 0) cout << i / 1000000 << endl;
        string s; cin >> s;
        if(M[s] != 0)
        {
            cout << M[s] << " " << i << endl;
            return 0;
        }
    }
    return 0;
}

'''