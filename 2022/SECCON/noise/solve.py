from PIL import Image
from pwn import * 
import time
from base64 import b64decode
from tqdm import tqdm

import itertools

FIN = [(1, 1), (1, -1), (-1, 1), (-1, -1), (1, 0), (-1, 0), (0, 1), (0, -1)]

def fade(x):
    return x * x * x * (x * (6 * x - 15) + 10)

def lerp(a, b, t):
    return (1 - t) * a + t * b

def dot_prod(A, B):
    assert len(A) == 2 and len(B) == 2
    return A[0] * B[0] + A[1] * B[1]

def isOKDetail(whi, st, S, pix):
    for i in range(20):
        for j in range(20):
            of_y = (5 * whi + 4 * (st + i) - 80) / 80
            of_x = (5 * whi + 4 * (st + j) - 80) / 80
            assert 0 <= of_x < 1 and 0 <= of_y < 1

            n00 = dot_prod(S[0], (of_x, of_y))
            n01 = dot_prod(S[1], (of_x, of_y - 1))
            n10 = dot_prod(S[2], (of_x - 1, of_y))
            n11 = dot_prod(S[3], (of_x - 1, of_y - 1))

            u = fade(of_x)
            v = fade(of_y)
            fin = lerp(lerp(n00, n10, u), lerp(n01, n11, u), v)
            fin = int((fin + 1) * 128)
            if abs(fin - pix[st + i, st + j][0]) > 1:
                return False
    return True

def isOk(whi, pix):
    st = (80 - 5 * whi + 3) // 4
    for S in itertools.product(FIN, repeat = 4):
        if isOKDetail(whi, st, S, pix):
            return True 
    return False

hex_flag = ""

for i in tqdm(range(42)):
    conn = remote("noiseccon.seccon.games", 1337)

    scale = 1 << (64 + 4 + 4 * i)
    for j in range(9):
        conn.recvline()
    conn.sendline(str(scale).encode())
    conn.sendline(str(scale).encode())
    img = conn.recvline().split()[-1]
    
    f = open("image.png", "wb")
    f.write(b64decode(img))
    f.close()    

    im = Image.open("image.png")
    pix = im.load()

    for whi in range(16):
        if isOk(whi, pix) == 1:
            hex_flag += hex(whi)[2:]
            break

    if len(hex_flag) % 2 == 0:
        print(bytes.fromhex(hex_flag[::-1]))

print(bytes.fromhex(hex_flag[::-1]))