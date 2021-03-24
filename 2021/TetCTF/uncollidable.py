HOST = "139.162.5.141"
PORT = 5555
 
r = remote(HOST, PORT)
 
key_id = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
 
tt = '294724a63e0fda8c731d9612b0a8e8b9bc0ec087ca9920c8488c5dd1df94ebff'
tt = bytes.fromhex(tt)
 
data = "1234"
 
for i in range(0, 10):
    key = '294724a63e0fda8c731d9612b0a8e8b9bc0ec087ca9920c8488c5dd1df94ebff'
    if i >= 1:
        key = bytes.fromhex(sha256(bytes.fromhex(key)).hexdigest())
        key = key[:-i]
        key = key.hex()
    request = {
        "action": "import_key",
        "key_id": key_id[i],
        "key": key
    }
    r.sendline(json.dumps(request))
    print(r.readline())
    request = {
        "action": "store_data",
        "key_id": key_id[i],
        "data": data
    }
    r.sendline(json.dumps(request))
    print(r.readline())
 
request = {
    "action": "report_bug"
}
 
r.sendline(json.dumps(request))
 
print(r.readline())
 
# TetCTF{HM4C_c4n_b3_m1sus3d-viettel:*100*718395803842748#}
