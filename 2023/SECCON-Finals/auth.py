from sage.all import * 
from pwn import * 
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, getPrime

HOST = "authenticator.int.seccon.games"
PORT = 8080

conn = remote(HOST, PORT)


def crc64(data: bytes, init: int) -> int:
    g = 0xcd8da4ff37e45ec3
    crc = init

    for x in data:
        crc = crc ^ x
        for _ in range(8):
            crc = ((crc >> 1) ^ (g * (crc & 1))) & 0xffffffffffffffff
    return crc


def crc64_vector(data):
    g = 0xcd8da4ff37e45ec3
    crc = []
    for i in range(64):
        crc.append(vector(GF(2), [0] * 65))
    for i in range(64):
        crc[i][i] = 1
    for x in data:
        for j in range(8):
            crc[56 + j][64] += ((int(x) >> (7 - j)) & 1)
        for j in range(8):
            new_crc = []
            for t in range(64):
                new_crc.append(vector(GF(2), [0] * 65))
            for i in range(1, 64):
                new_crc[i] = crc[i - 1]
            for i in range(64):
                new_crc[i] += (g >> (63 - i)) * crc[63]
            for i in range(64):
                crc[i] = new_crc[i]
    return crc 


def crc_via_init():
    g = 0xcd8da4ff37e45ec3
    crc = []
    for i in range(64):
        crc.append(vector(GF(2), [0] * 65))
    
    for i in range(8):
        for j in range(8):
            crc[56 + j][56 - 8 * i + j] += 1
        for j in range(8):
            new_crc = []
            for t in range(64):
                new_crc.append(vector(GF(2), [0] * 65))
            for i in range(1, 64):
                new_crc[i] = crc[i - 1]
            for i in range(64):
                new_crc[i] += (g >> (63 - i)) * crc[63]
            for i in range(64):
                crc[i] = new_crc[i]
    
    return crc 



# crc64("hint", ???) -> ???
def recover_from_hint(final_val):
    crc = crc64_vector(b"hint")
    M = Matrix(GF(2), 64, 64)
    v = vector(GF(2), [0] * 64)

    for i in range(64):
        for j in range(64):
            M[i, j] = crc[i][j] 
        v[i] = ((final_val >> (63 - i)) & 1) + crc[i][64]

    tt = M.solve_right(v)

    fin = 0
    for i in range(64):
        fin = 2 * fin + int(tt[i])

    return fin

# crc(x, 0) -> x?
def recover_from_data(final_val):
    crc = crc_via_init()
    M = Matrix(GF(2), 64, 64)
    v = vector(GF(2), [0] * 64)

    for i in range(64):
        for j in range(64):
            M[i, j] = crc[i][j] 
        v[i] = ((final_val >> (63 - i)) & 1) + crc[i][64]

    tt = M.solve_right(v)

    fin = 0
    for i in range(64):
        fin = 2 * fin + int(tt[i])

    return fin


def final_solution(data):
    crc = crc64_vector(data)
    M = Matrix(GF(2), 64, 64)
    v = vector(GF(2), [0] * 64)

    for i in range(64):
        for j in range(64):
            M[i, j] = crc[i][j] 
        M[i, i] -= 1
        v[i] = crc[i][64]

    tt = M.solve_right(v)

    fin = 0
    for i in range(64):
        fin = 2 * fin + int(tt[i])

    return fin


conn.recvline()
conn.recvline()

conn.sendline(b"H")

hint = int(conn.recvline().split()[-1].decode(), 16)

crc_key_t = recover_from_hint(hint)
key_t = recover_from_data(crc_key_t)

dat = key_t.to_bytes(8, "little")
answer = final_solution(dat)

fin = hex(answer)[2:]

conn.sendline(b"A")
conn.sendline(fin.encode())

print(conn.recvline())

print(conn.recvline())

print(conn.recvline())




'''

key: random 64 bits

auth(code, t)
    crc(key^t, code) == code

A -> find code such that auth(code, t) holds

H -> (hint, crc(key ^ t))

'''