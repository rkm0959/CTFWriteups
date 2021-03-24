F = GF(2**100)
d_1 = F.fetch_int(1)
d_2 = F.fetch_int(1)
gx, gy = (698546134536218110797266045394, 1234575357354908313123830206394)
px, py = (403494114976379491717836688842, 915160228101530700618267188624)
G = (F.fetch_int(gx), F.fetch_int(gy))
P = (F.fetch_int(px), F.fetch_int(py))

gx, gy = G
px, py = P

E = EllipticCurve(F, [F.fetch_int(1), d1 * d1 + d2, 0, 0, (d_1 ** 4) * ((d_1 ** 4) + (d_1 ** 2) + (d_2 ** 2))])

gnx = d_1 * (d_1 * d_1 + d_1 + d_2) * (gx + gy) / (gx * gy + d_1 * (gx + gy))
gny = d_1 * (d_1 * d_1 + d_1 + d_2) * (gx / (gx * gy + d_1 * (gx + gy)) + d_1 + 1)

pnx = d_1 * (d_1 * d_1 + d_1 + d_2) * (px + py) / (px * py + d_1 * (px + py))
pny = d_1 * (d_1 * d_1 + d_1 + d_2) * (px / (px * py + d_1 * (px + py)) + d_1 + 1)

GG = E(gnx, gny)
PP = E(pnx, pny)

print(discrete_log(PP, GG, operation='+'))