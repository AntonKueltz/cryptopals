from hashlib import sha1
from itertools import combinations
import re

import dsa
import padding
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


def verify_sig(m, sig, r):
    hexsig = util.int_to_hexstr(util.mod_exp(sig, r.e, r.n))
    i = hexsig.index('ff00')
    h = hexsig[i+4:i+44]
    return sha1(m).hexdigest() == h


def e_is_3_attack():
    r = rsa.RSA()
    m = "hi mom"
    h = sha1(m).hexdigest()

    mystr = chr(0x00) + chr(0x01) + chr(0xff) + chr(0x00)
    mystr += h.decode('hex')
    mystr += ((1024 / 8) - len(mystr)) * chr(0x00)

    forged = util.kth_root(int(mystr.encode('hex'), 16), r.e, rounded=True) + 1
    verified = verify_sig(m, forged, r)

    return 'Successfully forged \'hi mom\' sig' if verified else 'Sig failed'


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


def dsa_parameter_tampering():
    d = dsa.DSA()

    d.g = 0
    r, s = d.sign('Original Message')
    assert(d.verify('Bad Message', r, s))

    d.g = d.p + 1
    z = 2
    r = util.mod_exp(d.y, z, d.p) % d.q
    s = (r * util.mod_inv(z, d.q)) % d.q
    assert(d.verify('Hello World', r, s))
    assert(d.verify('Goodbye World', r, s))

    return 'Successfully signed "Hello World" and "Goodbye World"'


def rsa_parity_oracle():
    r = rsa.RSA()
    m = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBG' \
        'dW5reSBDb2xkIE1lZGluYQ=='.decode('base64')

    c = r.enc(m)
    bounds = [(0, 1), (1, 1)]

    for _ in range(r.n.bit_length()):
        nm = bounds[0][0] * bounds[1][1] + bounds[1][0] * bounds[0][1]
        dm = bounds[0][1] * bounds[1][1] * 2
        gcd = util.gcd(nm, dm)
        nm, dm = nm / gcd, dm / gcd

        c = (util.mod_exp(2, r.e, r.n) * c) % r.n

        if util.mod_exp(c, r.d, r.n) % 2 == 0:
            bounds[1] = (nm, dm)
        else:
            bounds[0] = (nm, dm)

    return util.int_to_ascii(bounds[1][0] * r.n / bounds[1][1])


def pkcs15_padding_oracle(c, cipher):
    m = cipher.dec(c)
    m = m.encode('hex').zfill(util.ceiling(cipher.n.bit_length(), 4))
    return m[:4] == '0002'


def rsa_pkcs15_oracle_easy():
    cipher = rsa.RSA(modsize=256)
    m = padding.pkcs1_5('kick it, CC', 256 / 8)

    c = cipher.enc(m)
    B = 2 ** (256 - 16)
    M = [2*B, 3*B-1]
    i = 1
    update_c = lambda s: (c * util.mod_exp(s, cipher.e, cipher.n)) % cipher.n

    while not M[0] == M[1]:
        a, b = M[0], M[1]

        if i == 1:
            s = util.ceiling(cipher.n, 3*B)
            c_ = update_c(s)

            while not pkcs15_padding_oracle(c_, cipher):
                s += 1
                c_ = update_c(s)

        else:
            r = util.ceiling(2 * (b*s - 2*B), cipher.n)
            s = util.ceiling(2*B + r*cipher.n, b)
            c_ = update_c(s)

            while not pkcs15_padding_oracle(c_, cipher):
                if s >= (3*B + r*cipher.n) / a:
                    r += 1
                    s = util.ceiling(2*B + r*cipher.n, b)

                else:
                    s += 1

                c_ = update_c(s)

        r = util.ceiling((a*s - 3*B + 1), cipher.n)
        M[0] = max(a, util.ceiling(2*B + r*cipher.n, s))
        M[1] = min(b, (3*B - 1 + r*cipher.n) / s)
        i += 1

    return padding.validate1_5(util.int_to_ascii(M[0]))


def rsa_pkcs15_oracle_complete():
    cipher = rsa.RSA(modsize=768)
    m = padding.pkcs1_5('kick it, CC', 768 / 8)

    c = cipher.enc(m)
    B = 2 ** (768 - 16)
    M = [(2*B, 3*B-1)]
    i = 1
    update_c = lambda s: (c * util.mod_exp(s, cipher.e, cipher.n)) % cipher.n

    while not (len(M) == 1 and M[0][0] == M[0][1]):
        if i == 1:
            s = util.ceiling(cipher.n, 3*B)
            c_ = update_c(s)

            while not pkcs15_padding_oracle(c_, cipher):
                s += 1
                c_ = update_c(s)

        elif len(M) >= 2:
            s += 1
            c_ = update_c(s)

            while not pkcs15_padding_oracle(c_, cipher):
                s += 1
                c_ = update_c(s)

        else:
            a, b = M[0][0], M[0][1]
            r = util.ceiling(2 * (b*s - 2*B), cipher.n)
            s = util.ceiling(2*B + r*cipher.n, b)
            c_ = update_c(s)

            while not pkcs15_padding_oracle(c_, cipher):
                if s >= (3*B + r*cipher.n) / a:
                    r += 1
                    s = util.ceiling(2*B + r*cipher.n, b)

                else:
                    s += 1

                c_ = update_c(s)

        newM = []
        for (a, b) in M:
            rlow = util.ceiling((a*s - 3*B + 1), cipher.n)
            rhigh = (b*s - 2*B) / cipher.n

            for r in range(rlow, rhigh + 1):
                newa = max(a, util.ceiling(2*B + r*cipher.n, s))
                newb = min(b, (3*B - 1 + r*cipher.n) / s)
                newM.append((newa, newb))

        M = list(set(newM))
        i += 1

    return padding.validate1_5(util.int_to_ascii(M[0][0]))
