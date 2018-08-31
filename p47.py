from binascii import hexlify, unhexlify
from os import urandom

from p39 import RSA


def ceiling(a, b):
    return (a / b) + (1 if a % b else 0)


def pkcs15(m, mod_bytes):
    padlen = mod_bytes - 3 - len(m)
    pad = '\x00\x02'

    if padlen < 8:
        raise ValueError("Not enough bytes for padding", 1.5)

    pad += urandom(padlen)
    pad += '\x00'
    assert len(pad + m) == mod_bytes
    return pad + m


def pkcs15_padding_oracle(c, rsa):
    m = hex(rsa.dec(c))[2:-1]
    m = m.zfill(ceiling(rsa.N.bit_length(), 4))
    return m[:4] == '0002'


def validate_pkcs15(ptxt):
    if ptxt[0] != '\x02':
        raise ValueError('First bytes not 0x0002')

    try:
        idx = ptxt[1:].index('\x00')
    except IndexError:
        raise ValueError('No 0x00 delimiter found!')

    return ptxt[2+idx:]


def p47():
    rsa = RSA(bitsize=256)
    m = pkcs15('kick it, CC', 256 / 8)
    m = int(hexlify(m), 16)

    c = rsa.enc(m)
    B = 2 ** (256 - 16)
    M = [2 * B, 3 * B-1]
    i = 1

    def update_ctxt(s):
        return (c * pow(s, rsa.e, rsa.N)) % rsa.N

    while not M[0] == M[1]:
        a, b = M[0], M[1]

        if i == 1:
            s = ceiling(rsa.N, 3*B)
            c_ = update_ctxt(s)

            while not pkcs15_padding_oracle(c_, rsa):
                s += 1
                c_ = update_ctxt(s)

        else:
            r = ceiling(2 * (b * s - 2 * B), rsa.N)
            s = ceiling(2 * B + r * rsa.N, b)
            c_ = update_ctxt(s)

            while not pkcs15_padding_oracle(c_, rsa):
                if s >= (3 * B + r * rsa.N) / a:
                    r += 1
                    s = ceiling(2 * B + r * rsa.N, b)

                else:
                    s += 1

                c_ = update_ctxt(s)

        r = ceiling((a * s - 3 * B + 1), rsa.N)
        M[0] = max(a, ceiling(2 * B + r * rsa.N, s))
        M[1] = min(b, (3 * B - 1 + r * rsa.N) / s)
        i += 1

    hex_data = hex(M[0])[2:-1]
    recovered = unhexlify(hex_data.zfill(len(hex_data) + (len(hex_data) % 2)))
    return 'Recovered message "{}"'.format(validate_pkcs15(recovered))


def main():
    from main import Solution
    return Solution('47: Bleichenbacher\'s PKCS 1.5 Padding Oracle (Simple Case)', p47)
