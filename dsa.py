from hashlib import sha1

from Crypto.Random import random

import util


class DSA():
    def __init__(self):
        self.p = int(
            '800000000000000089e1855218a0e7dac38136ffafa72eda7'
            '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
            '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
            'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
            'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
            '1a584471bb1', 16
        )
        self.q = int('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)
        self.g = int(
            '5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119'
            '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5'
            '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047'
            '0f5b64c36b625a097f1651fe775323556fe00b3608c887892'
            '878480e99041be601a62166ca6894bdd41a7054ec89f756ba'
            '9fc95302291', 16
        )

        self.x = random.randint(1, self.q-1)
        self.y = util.mod_exp(self.g, self.x, self.p)

    def sign(self, m):
        r, s = 0, 0

        # while r == 0 or s == 0:
        k = random.randint(1, self.q-1)
        r = util.mod_exp(self.g, k, self.p) % self.q

        hash_int = int(sha1(m).hexdigest(), 16)
        s = (util.mod_inv(k, self.q) * (hash_int + self.x * r)) % self.q

        return (r, s)

    def verify(self, m, r, s):
        '''
        if r <= 0 or r >= self.q or s <= 0 or s >= self.q:
            print "BAD FAIL"
            return False
        '''
        w = util.mod_inv(s, self.q)
        u1 = (int(sha1(m).hexdigest(), 16) * w) % self.q
        u2 = (r * w) % self.q

        v1 = util.mod_exp(self.g, u1, self.p)
        v2 = util.mod_exp(self.y, u2, self.p)
        v = ((v1 * v2) % self.p) % self.q

        return v == r
