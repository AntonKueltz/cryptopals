from hashlib import sha1
from typing import Optional

from main import Solution
from p39 import invmod

from Crypto.Random.random import randint


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

        self.x = randint(1, self.q - 1)
        self.y = pow(self.g, self.x, self.p)

    def sign(self, m: bytes) -> (int, int):
        r, s = 0, 0

        k = randint(1, self.q - 1)
        r = pow(self.g, k, self.p) % self.q

        hash_int = int(sha1(m).hexdigest(), 16)
        s = (invmod(k, self.q) * (hash_int + self.x * r)) % self.q

        return r, s

    def verify(self, m:  bytes, r: int, s: int) -> bool:
        w = invmod(s, self.q)
        u1 = (int(sha1(m).hexdigest(), 16) * w) % self.q
        u2 = (r * w) % self.q

        v1 = pow(self.g, u1, self.p)
        v2 = pow(self.y, u2, self.p)
        v = ((v1 * v2) % self.p) % self.q

        return v == r


def p43() -> Optional[str]:
    dsa = DSA()
    y = int(
        '84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4'
        'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004'
        'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed'
        '1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b'
        'bb283e6633451e535c45513b2d33c99ea17', 16
    )

    m = b'For those that envy a MC it can be hazardous to your health\n' \
        b'So be friendly, a matter of life and death, just like a etch-a-sketch\n'
    mhash = int(sha1(m).hexdigest(), 16)
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

    fingerprint = '0954edd5e0afe5542a4adf012611a91912a3ec16'

    for k in range(2**16):
        x = (((s * k) - mhash) * invmod(r, dsa.q)) % dsa.q

        if sha1(hex(x)[2:].encode()).hexdigest() == fingerprint:
            assert y == pow(dsa.g, x, dsa.p)
            return f'Private DSA key is {x}'


def main() -> Solution:
    return Solution('43: DSA key recovery from nonce', p43)
