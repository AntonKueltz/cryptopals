from hashlib import sha1
from itertools import combinations
from re import findall
from typing import Collection, Optional

from main import Solution
from p39 import invmod
from p43 import DSA


def _parse_signature_file() -> Collection[str]:
    pattern = r'msg: [a-zA-Z.,\' ]+\n' \
              r's: ([0-9]+)\n' \
              r'r: ([0-9]+)\n' \
              r'm: ([0-9a-f]+)\n?'

    with open('Data/44.txt') as f:
        s = f.read()

    return findall(pattern, s)


def p44() -> Optional[str]:
    dsa = DSA()
    y = int(
        '2d026f4bf30195ede3a088da85e398ef869611d0f68f07'
        '13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8'
        '5519b1c23cc3ecdc6062650462e3063bd179c2a6581519'
        'f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430'
        'f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3'
        '2971c3de5084cce04a2e147821', 16
    )

    fingerprint = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'
    sigs = _parse_signature_file()

    for i, j in combinations(range(len(sigs)), 2):
        s1, m1 = int(sigs[i][0]), int(sigs[i][2], 16)
        s2, m2 = int(sigs[j][0]), int(sigs[j][2], 16)

        s = (s1 - s2) % dsa.q
        m = (m1 - m2) % dsa.q
        k = (invmod(s, dsa.q) * m) % dsa.q

        r = int(sigs[i][1])
        x = (((s1 * k) - m1) * invmod(r, dsa.q)) % dsa.q

        if sha1(hex(x)[2:].encode()).hexdigest() == fingerprint:
            assert y == pow(dsa.g, x, dsa.p)
            return f'Private DSA key is {x}'


def main() -> Solution:
    return Solution('44: DSA nonce recovery from repeated nonce', p44)
