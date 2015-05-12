from Crypto.Util import number

import util


class RSA():
    def __init__(self, modsize=1024):
        phiN = 0

        while util.gcd(3, phiN) != 1:
            p, q = number.getPrime(modsize / 2), number.getPrime(modsize / 2)
            N, phiN = p * q, (p-1) * (q-1)

        e = 3
        d = util.mod_inv(e, phiN)

        self.n, self.e, self.d = N, e, d

    def enc(self, m):
        mval = int(m.encode('hex'), 16)
        return util.mod_exp(mval, self.e, self.n)

    def dec(self, c):
        m = util.mod_exp(c, self.d, self.n)
        return util.int_to_ascii(m)
