from sage.rings.all import *

N = 10
e = 4 * N**2 + 12 * N - 3
f = 32 * (N + 3)

eq = EllipticCurve([0, e, 0, f, 0])

rank = eq.rank()

generators = eq.gens()

P = generators[0]


def find_original_point(P, N):
    a, b = P[0], P[1]
    x = (8 * (N + 3) - a + b) / (2 * (N + 3) * (4 - a))
    y = (8 * (N + 3) - a - b) / (2 * (N + 3) * (4 - a))
    z = (-4 * (N + 3) - (N + 2) * a) / ((N + 3) * (4 - a))
    lcm_denominator = lcm(denominator(x), lcm(denominator(y), denominator(z)))
    return [x * lcm_denominator, y * lcm_denominator, z * lcm_denominator]


original_point = find_original_point(P, N)
print("Original point:", original_point)

m = 1

while True:
    u = find_original_point(m * P, N)

    if all(coord > 0 for coord in u[:3]):
        x, y, z = u[0], u[1], u[2]
        print("x =", x)
        print("y =", y)
        print("z =", z)
        break
    else:
        print(f"m={m} didn't yield in positive values")

    m += 1

from pwn import *

conn = remote("localhost", 49428)

conn.sendlineafter(b"Enter the value for x: ", str(x).encode())
conn.sendlineafter(b"Enter the value for y: ", str(y).encode())
conn.sendlineafter(b"Enter the value for z: ", str(z).encode())

print(conn.recvall().decode().strip())
