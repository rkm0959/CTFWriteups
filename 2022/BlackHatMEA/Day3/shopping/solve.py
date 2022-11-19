from secrets import randbelow
import os, base64, hashlib
from Crypto.Util.number import getPrime, isPrime, long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from sage.all import *
from tqdm import tqdm
from pwn import *

LMAO = b"""|  ~ Options ::
|    [1] Show account info
|    [2] List my active chats
|    [3] Open a chat
|
|  ~ Developer options ::
|    [4] Send a raw packet to the Server
|
|  ~ [0] Exit"""


MYNAME = "xXx_h4x0r_xXx"

url = "blackhat4-a10bd2bd125f81495ac4b63074bf9870-0.chals.bh.ctf.sa"
conn = remote(url, 443, ssl=True, sni=url)


conn.recvlines(10)

g = 2 
p = int(conn.recvline().split()[-1])


conn.recvuntil(LMAO)
conn.recvline()

conn.sendline(b"1")

conn.recvlines(5)

MY_USER_ID = conn.recvline().split()[-1].decode()

MY_USER_PK = int(conn.recvline().split()[-1].decode())

conn.recvline()
conn.recvuntil(LMAO)

conn.recvline()

conn.sendline(b"2")
cc = conn.recvlines(21)

ALICE_ME_ID = cc[7].split()[-1].decode()
ALICE_ME_PK = int(cc[8].split()[-1].decode())

PARTY_ID = cc[13].split()[-1].decode()
PARTY_PK = int(cc[14].split()[-1].decode())

BOB_ME_ID = cc[19].split()[-1].decode()
BOB_ME_PK = int(cc[20].split()[-1].decode())

conn.recvuntil(LMAO)
conn.recvline()

conn.sendline(b"3")
conn.sendline(b"0")
conn.sendline(b"1")
conn.sendline(b"hi")

conn.recvuntil(LMAO)
conn.recvline()

conn.sendline(b"3")
conn.sendline(b"0")
conn.sendline(b"1")
conn.sendline(b"give me flag")

conn.recvuntil(LMAO)

conn.sendline(b"3")
conn.sendline(b"1")
conn.sendline(b"1")
conn.sendline(b"plz")

print("ME", MY_USER_ID, MY_USER_PK)
print("ALICE_ME", ALICE_ME_ID, ALICE_ME_PK)
print("PARTY", PARTY_ID, PARTY_PK)
print("BOB", BOB_ME_ID, BOB_ME_PK)

def send_packet(packet):
    conn.recvuntil(LMAO)
    conn.sendline(b"4")
    conn.sendline(packet)
    conn.interactive()

def get_ID(name, pk):
    return hashlib.sha256((name + str(pk) + 'DiffieChat Ver {}'.format("3.14")).encode()).hexdigest()


assert MY_USER_ID == get_ID(MYNAME, MY_USER_PK)
assert ALICE_ME_ID == get_ID("Alice", ALICE_ME_PK)
assert BOB_ME_ID == get_ID("Bob", BOB_ME_PK)


group_sk = pow(2, PARTY_PK, p)

def encrypt(msg: str, secret: int, key_ID, recip_ID: str):
    if type(msg) == str:
        msg = msg.encode()
    # Get message parameters
    msg   = msg.replace(b':',b'')
    while len(msg) % 16 != 0:
        msg += b' '
    salt   = os.urandom(8)
    # Get encryption parameters
    Ke     = hashlib.sha256('{:02x}:{}:{}'.format(int(secret), salt.hex(), 'Key').encode()).digest()
    IVpre  = hashlib.sha256('{:02x}:{}:{}'.format(int(secret), salt.hex(), 'IV').encode()).digest()
    IVe    = long_to_bytes(bytes_to_long(IVpre[:16]) ^ bytes_to_long(IVpre[16:]))
    # Cipher text
    C      = AES.new(Ke, AES.MODE_CBC, IVe).encrypt(msg)
    # Authentication
    V      = hashlib.sha256(C).digest()
    Tpre   = long_to_bytes(bytes_to_long(V[:16]) ^ bytes_to_long(V[16:]))
    T      = AES.new(Ke, AES.MODE_ECB).encrypt(Tpre)
    # Create packet (to send to the server)
    packet = '{}:{}:{}:{}:{}:{}:{}'.format('DiffieChat Ver {}'.format("3.14"), int(time.time()), salt.hex(), C.hex(), T.hex(), key_ID, recip_ID)
    return packet


packet = encrypt("ok, send flag", group_sk, BOB_ME_ID, PARTY_ID)

send_packet(packet)
