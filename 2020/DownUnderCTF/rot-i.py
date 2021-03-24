t = 'ypw zj zwufpp hwu txadjkcq dtbtyu kqkwxrbvu! mbz cjzg kv iajbo{ndldie_al_aqk_jjrnsxee}. xzi utj gnn olkd qgq ftk ykaqe uei mbz ocrt qi ynlu, etrm mffn wij bf wlny mjcj :'
u = 'the flag is ductf'
v = 'mbz cjzg kv iajbo'
 
for i in range(0, 26):
    s = ""
    st = i
    for j in range(len(t)):
        if ord('a') <= ord(t[j]) <= ord('z'):
            cc = chr(ord('a') + (ord(t[j]) - ord('a') + st) % 26)
            s += cc
        else:
            s += t[j]
        st = st - 1
    print(s)