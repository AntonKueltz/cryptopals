from fractions import gcd

from Crypto.Util.number import getPrime


def invmod(n, mod):
    n = n % mod
    t, newt = 0, 1
    r, newr = mod, n

    while newr != 0:
        q = r / newr
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
    def __init__(self, bitsize=1024):
        self.e = 3
        p, q = getPrime(bitsize / 2), getPrime(bitsize / 2)
        phi, self.N = (p - 1) * (q - 1), p * q

        while gcd(phi, self.e) != 1:
            p, q = getPrime(bitsize / 2), getPrime(bitsize / 2)
            phi, self.N = (p - 1) * (q - 1), p * q

        self._d = invmod(self.e, phi)

    def enc(self, m):
        return pow(m, self.e, self.N)

    def dec(self, c, tostr=False):
        return pow(c, self._d, self.N)


def p39():
    m = 42
    rsa = RSA(bitsize=32)
    print 'Initialized 32 bit RSA: e = {}, N = {}'.format(rsa.e, rsa.N)
    c = rsa.enc(m)
    print 'Enc({}) = {}'.format(m, c)
    return 'Dec({}) = {}'.format(c, rsa.dec(c))


def main():
    from main import Solution
    return Solution('39: Implement RSA', p39)
