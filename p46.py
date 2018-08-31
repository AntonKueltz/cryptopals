from base64 import b64decode
from binascii import hexlify, unhexlify
from fractions import gcd as gcd_func

from p39 import RSA


def p46():
    rsa = RSA()
    m = b64decode(
        'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBG'
        'dW5reSBDb2xkIE1lZGluYQ=='
    )

    m = int(hexlify(m), 16)
    c = rsa.enc(m)
    bounds = [(0, 1), (1, 1)]

    for _ in range(rsa.N.bit_length()):
        nm = bounds[0][0] * bounds[1][1] + bounds[1][0] * bounds[0][1]
        dm = bounds[0][1] * bounds[1][1] * 2
        gcd = gcd_func(nm, dm)
        nm, dm = nm / gcd, dm / gcd

        c = (pow(2, rsa.e, rsa.N) * c) % rsa.N

        if rsa.dec(c) % 2 == 0:
            bounds[1] = (nm, dm)
        else:
            bounds[0] = (nm, dm)

    recovered = bounds[1][0] * rsa.N / bounds[1][1]
    return 'Recovered message "{}"'.format(unhexlify(hex(recovered)[2:-1]))


def main():
    from main import Solution
    return Solution('46: RSA parity oracle', p46)
