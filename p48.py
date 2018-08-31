from binascii import hexlify, unhexlify
from os import urandom

from p39 import RSA
from p47 import ceiling, pkcs15, pkcs15_padding_oracle, validate_pkcs15


def p48():
    rsa = RSA(bitsize=768)
    m = pkcs15('kick it, CC', 768 / 8)
    m = int(hexlify(m), 16)

    c = rsa.enc(m)
    B = 2**(768 - 16)
    M = [(2 * B, 3 * B-1)]
    i = 1

    def update_ctxt(s):
        return (c * pow(s, rsa.e, rsa.N)) % rsa.N

    while not (len(M) == 1 and M[0][0] == M[0][1]):
        if i == 1:
            s = ceiling(rsa.N, 3 * B)
            c_ = update_ctxt(s)

            while not pkcs15_padding_oracle(c_, rsa):
                s += 1
                c_ = update_ctxt(s)

        elif len(M) >= 2:
            s += 1
            c_ = update_ctxt(s)

            while not pkcs15_padding_oracle(c_, rsa):
                s += 1
                c_ = update_ctxt(s)

        else:
            a, b = M[0][0], M[0][1]
            r = ceiling(2 * (b*s - 2*B), rsa.N)
            s = ceiling(2*B + r*rsa.N, b)
            c_ = update_ctxt(s)

            while not pkcs15_padding_oracle(c_, rsa):
                if s >= (3*B + r*rsa.N) / a:
                    r += 1
                    s = ceiling(2*B + r*rsa.N, b)

                else:
                    s += 1

                c_ = update_ctxt(s)

        newM = []
        for (a, b) in M:
            rlow = ceiling((a * s - 3 * B + 1), rsa.N)
            rhigh = (b * s - 2 * B) / rsa.N

            for r in range(rlow, rhigh + 1):
                newa = max(a, ceiling(2 * B + r * rsa.N, s))
                newb = min(b, (3 * B - 1 + r * rsa.N) / s)
                newM.append((newa, newb))

        M = list(set(newM))
        i += 1

    hex_data = hex(M[0][0])[2:-1]
    recovered = unhexlify(hex_data.zfill(len(hex_data) + (len(hex_data) % 2)))
    return 'Recovered message "{}"'.format(validate_pkcs15(recovered))


def main():
    from main import Solution
    return Solution('48: Bleichenbacher\'s PKCS 1.5 Padding Oracle (Complete Case)', p48)
