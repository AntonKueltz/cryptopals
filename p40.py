from binascii import hexlify, unhexlify
from typing import Optional

from main import Solution
from p39 import RSA, invmod


def kth_root(n: int, k: int, rounded: bool = False) -> Optional[int]:
    bits = len(bin(n)[2:])
    mn, mx = (2**(bits // k)), (2**(bits // k + 1))
    mid = (mx + mn) // 2
    guess = mid**k

    while guess != n:
        if mn > mx or mn**k > n or mx**k < n:
            return None
        elif n > guess:
            mn = mid
        else:
            mx = mid

        mid = (mx + mn) // 2

        if mid**k == guess:
            if rounded:
                return mid
            else:
                return None
        else:
            guess = mid**k

    return mid


def p40() -> str:
    msg = b'Assume you\'re a Javascript programmer. That is, you\'re using a naive handrolled ' \
          b'RSA to encrypt without padding.'
    print(f'Encrypting secret message "{msg.decode()}"')
    msg = int(hexlify(msg), 16)

    pairs = []
    for _ in range(3):
        rsa = RSA()
        c = rsa.enc(msg)
        pairs.append((c, rsa.N))
        print(f'Generated ciphertext = {str(c)[:15]}... for N = {str(rsa.N)[:15]}...')

    c0, c1, c2 = [c for (c, _) in pairs]
    n0, n1, n2 = [N for (c, N) in pairs]
    m0, m1, m2 = n1 * n2, n0 * n2, n0 * n1

    t0 = (c0 * m0 * invmod(m0, n0))
    t1 = (c1 * m1 * invmod(m1, n1))
    t2 = (c2 * m2 * invmod(m2, n2))
    c = (t0 + t1 + t2) % (n0 * n1 * n2)

    m = kth_root(c, 3)
    m = unhexlify(hex(m)[2:])

    return f'Recovered message "{m.decode()}"'


def main() -> Solution:
    return Solution('40: Implement an E=3 RSA Broadcast attack', p40)
