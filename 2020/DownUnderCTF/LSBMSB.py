print(conn.recvline())
print(conn.recvline())
print(conn.recvline())
print(conn.recvline())
 
num = []
for i in range(1, 24):
    if i <= 12:
        conn.recvline()
        conn.send("0\n")
        T = conn.recvline()
        cc = 'Unlucky! The number was '
        T = T[len(cc):-1]
        T = T.decode()
        num.append(int(T))
    if i == 12:
        print(num)
    if i >= 13:
        conn.recvline()
        x = int(input())
        conn.send(str(x) + " " + str(x) + "\n")
        conn.recvline()
print(conn.recvline())

# sage

def Babai_closest_vector(M, G, target):
        small = target
        for _ in range(1):
            for i in reversed(range(M.nrows())):
                c = ((small * G[i]) / (G[i] * G[i])).round()
                small -=  M[i] * c
        return target - small  
 
n = 937954372991277727569919570466170502903005281412586514689603
a = 340191373049582240414926177838297382326391494482892283959227
num = [766060457621, 362859134107, 54864930141, 719063617319, 570095548300, 385643485103, 400992666914, 1095280053170, 105685083393, 701621243850, 981672150015, 408709955639]
 
low = []
upp = []
for x in num:
    low.append(x >> 20)
    upp.append(x % (2 ** 20))
 
mult_1 = [a]
mult_2 = [1]
 
for i in range(1, 12):
    mult_1.append((a * mult_1[i-1]) % n)
    mult_2.append((a * mult_2[i-1] + 1) % n)
 
M = Matrix(ZZ, 14, 14)
iv = inverse_mod(2 ** 20, n)
 
for i in range(0, 12):
    M[0, i] = ((int)(mult_1[i] * iv % n)) * n
M[0, 12] = 1
 
for i in range(0, 12):
    M[1, i] = ((int)(mult_2[i] * iv % n)) * n
M[1, 13] = 1
 
for i in range(0, 12):
    M[i+2, i] = n * n
 
Target = [0] * 14
for i in range(0, 12):
    Target[i] = (((2 ** 160) * upp[i] + iv * low[i]) % n + (2 ** 159)) * n
Target[12] = n // 2
Target[13] = n // 2
               
M = M.LLL()
GG = M.gram_schmidt()[0]
Target = vector(Target)
TT = Babai_closest_vector(M, GG, Target)
x = TT[12]
c = TT[13]
 
for i in range(1, 24):
    x = (a * x + c) % n
    if i <= 12:
        print(x % (2 **  20) == low[i-1])
        print((x >> 180) == upp[i-1])
    if i >= 13:
        print( ((x % (2 ** 20)) << 20) + (x >> 180)) 
