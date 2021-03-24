T = conn.recvline()
cc = 'Hey there, have a message cashcashcashcash and its signature '
SIG = T[len(cc) : -2]
SIG = bytes.fromhex(SIG.decode())
INC = SIG[0:16]
IV = SIG[16:32]
ms = b'cashcashcashcash'
goal = "flagflagflagflag"
conn.send(goal + "\n")
TT = INC + bytexor(ms, bytexor(IV, goal.encode()))
conn.send(TT.hex() + "\n")
print(conn.recvline())
conn.send(TT.hex() + "\n")
print(bytes.fromhex(TT.hex()))
print(conn.recvline())
print(conn.recvline())