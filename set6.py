from hashlib import sha1
from itertools import combinations
import re

import dsa
import rsa
import util


def rsa_recovery_oracle():
    r = rsa.RSA()
    N, e = r.n, r.e

    ptxt = raw_input('Enter some text: ')
    ctxt = r.enc(ptxt)

    s = 2
    ctxt_ = util.mod_exp(s, e, N) * ctxt % N
    ascii_ptxt = r.dec(ctxt_)
    ptxt_ = int(ascii_ptxt.encode('hex'), 16)

    return util.int_to_ascii(util.mod_inv(s, N) * ptxt_ % N)


def dsa_key_recovery():
    d = dsa.DSA()
    y = int(
        '84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4'
        'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004'
        'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed'
        '1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b'
        'bb283e6633451e535c45513b2d33c99ea17', 16
    )

    m = 'For those that envy a MC it can be hazardous to your health\n' \
        'So be friendly, a matter of life and death, just like a ' \
        'etch-a-sketch\n'
    mhash = int(sha1(m).hexdigest(), 16)
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

    fingerprint = '0954edd5e0afe5542a4adf012611a91912a3ec16'

    for k in range(2**16):
        x = (((s * k) - mhash) * util.mod_inv(r, d.q)) % d.q

        if sha1(util.int_to_hexstr(x)).hexdigest() == fingerprint:
            assert(y == util.mod_exp(d.g, x, d.p))
            return x


def parse_signature_file():
    pattern = r'msg: [a-zA-Z.,\' ]+\n' \
              r's: ([0-9]+)\n' \
              r'r: ([0-9]+)\n' \
              r'm: ([0-9a-f]+)\n?'

    f = open('Data/44.txt')
    s = f.read()
    f.close()

    return re.findall(pattern, s)


def dsa_repeated_nonce_recovery():
    d = dsa.DSA()
    y = int(
        '2d026f4bf30195ede3a088da85e398ef869611d0f68f07'
        '13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8'
        '5519b1c23cc3ecdc6062650462e3063bd179c2a6581519'
        'f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430'
        'f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3'
        '2971c3de5084cce04a2e147821', 16
    )

    fingerprint = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'

    sigs = parse_signature_file()

    for i, j in combinations(range(len(sigs)), 2):
        s1, m1 = int(sigs[i][0]), int(sigs[i][2], 16)
        s2, m2 = int(sigs[j][0]), int(sigs[j][2], 16)

        s = (s1 - s2) % d.q
        m = (m1 - m2) % d.q
        k = (util.mod_inv(s, d.q) * m) % d.q

        r = int(sigs[i][1])
        x = (((s1 * k) - m1) * util.mod_inv(r, d.q)) % d.q

        if sha1(util.int_to_hexstr(x)).hexdigest() == fingerprint:
            assert(y == util.mod_exp(d.g, x, d.p))
            return x
