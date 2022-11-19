import requests 
from tqdm import tqdm 
import random as rand
import string 

def getToken(username):
    url = "https://blackhat4-336336aaf03cbd1485f05d71350b9955-0.chals.bh.ctf.sa/"
    conn = requests.get(url + "register/" + username, allow_redirects=False)
    token = conn.headers["Set-Cookie"].split(";")

    for x in token:
        if 'token' in x:
            token = x
            break
    token = token[6:]

    return token 

lmao = b'<!doctype html>\n\n<head>\n  <link rel="stylesheet" type="text/css" href="/static/page.css">\n</head>\n\n<title>Webbed</title>\n\n<div class="top">\n\n  <h1>Webbed</h1>\n\n</div>\n\n<div class="bottom">\n\n  \n\n    \n\n      \n\n        <div class="flash_error">\n\n          <strong>Invalid login token.</strong>\n\n        </div>\n\n      \n\n    \n\n  \n\n  \n\n    \n\n  \n\n</div>\n\n\n\n  <div class="center">\n\n    Log in using token cookie at <span style="color:#bb5920">/login/&lt;username&gt;/</span>\n\n    <br>\n    <br>\n\n    Register to create a token at <span style="color:#bb5920">/register/&lt;username&gt;/</span>\n\n    <br>\n    <br>\n    <br>\n    <br>\n\n    <i>Hint: you can use Python\'s requests module to automate the communication with the website.</i>\n\n  </div>\n\n'

def loginAttempt(username, token):
    url = "https://blackhat4-336336aaf03cbd1485f05d71350b9955-0.chals.bh.ctf.sa/"
    conn = requests.get(url + "login/" + username, allow_redirects=True, cookies = {"token": token})
    if conn.content != lmao:
        print(conn.content)

def byteXor(a, b):
    assert len(a) == 16 and len(b) == 16
    return bytes(u ^ v for (u, v) in zip(a, b))

for i in tqdm(range(20000)):
    rd = "".join((rand.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(15)))
    token = getToken(rd)
    enc = bytes.fromhex(token)
    IV = enc[:16]
    C1 = enc[16:32]
    C2 = enc[32:48]
    C3 = enc[48:64]

    new_cc = IV + C1 + byteXor(C2, byteXor(b'"admin": false}\x01', b',"admin": true}\x01')) + C3
    loginAttempt(rd[:2], new_cc.hex())