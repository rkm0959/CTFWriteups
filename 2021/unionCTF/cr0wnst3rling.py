q_grid = get_q_grid(75005) 
enc = bytes.fromhex('76f64667220717784affa07cf6b8be52c7d8348d778a41615efa9e53f2566b27fd96eb984c08')
fib = [0, 1]
for i in range(2, 50):
    fib.append(fib[i-1] + fib[i-2])
 
# the first note of the musical key does not matter since the key_index will become 1 anyway
 
# known plaintext
ptxt = "union"
for i in range(0, 5):
    if i == 0: # first note doesn't matter
        continue
    for j in range(1, 8): # try all 7 possible notes
        idx = (j ** i) * fib[i]
        q = q_grid[idx] # we assume idx < actual length of q_grid
        key_byte_hex = bbp_pi(q)
        out = enc[i] ^ int(key_byte_hex, 16)
        if out == ord(ptxt[i]): # match
            print(chr(64 + j)) # output the note
 
# results in C D A D -> set the first five notes as A C D A D
 
 
# brute force 7^3
for i in range(0, 7):
    for j in range(0, 7):
        for k in range(0, 7):
            T = ['A', 'C', 'D', 'A', 'D', chr(65+i), chr(65+j), chr(65+k)]
            key_indexes , size = get_key(T)
            # remove the assertion for size in get_key
            if size >= 75000:
                continue
            # compute the "actual" q_grid
            q_qgrid = []
            for val in q_grid:
                if val < size:
                    q_qgrid.append(val)
            # compute the plaintext
            out = []
            for ii in range(0, len(enc)):
                idx = key_indexes[ii % 8] * fib[ii]
                q = q_qgrid[idx % len(q_qgrid)]
                key_byte_hex = bbp_pi(q)
                out.append(enc[ii] ^ int(key_byte_hex, 16))
            print(bytes(out)) # wait for it..
