from math import gcd

from main import Solution

from Crypto.Util.number import getPrime, getRandomInteger


def invmod(n: int, mod: int) -> int:
    n = n % mod
    t, newt = 0, 1
    r, newr = mod, n

    while newr != 0:
        q = r // newr
        tmp1, tmp2 = t, r

        t = newt
        newt = tmp1 - q * newt
        r = newr
        newr = tmp2 - q * newr

    if r > 1:
        return 0
    elif t < 0:
        return t + mod
    else:
        return t


class RSA:
    def __init__(self, bitsize: int = 1024):
        self.e = 3
        self.bitsize = bitsize

        p, q = getPrime(bitsize // 2), getPrime(bitsize // 2)
        while int.bit_length(p * q) != bitsize:
            p, q = getPrime(bitsize // 2), getPrime(bitsize // 2)

        phi, self.N = (p - 1) * (q - 1), p * q

        while gcd(phi, self.e) != 1:
            p, q = getPrime(bitsize // 2), getPrime(bitsize // 2)
            phi, self.N = (p - 1) * (q - 1), p * q

        self._d = invmod(self.e, phi)

    def enc(self, m: int) -> int:
        return pow(m, self.e, self.N)

    def dec(self, c: int) -> int:
        return pow(c, self._d, self.N)


def p39() -> str:
    m = getRandomInteger(31)
    rsa = RSA(bitsize=32)
    print(f'Initialized 32 bit RSA: e = {rsa.e}, N = {rsa.N}')
    c = rsa.enc(m)
    print(f'Enc({m}) = {c}')
    return f'Dec({c}) = {rsa.dec(c)}'


def main() -> Solution:
    return Solution('39: Implement RSA', p39)
