from binascii import hexlify, unhexlify
from json import dumps, loads

from p39 import RSA, invmod


def p41():
    rsa = RSA()
    N, e = rsa.N, rsa.e

    ptxt = dumps({
        'time': 1356304276,
        'social': '555-55-5555',
    })
    ptxt = int(hexlify(ptxt), 16)
    ctxt = rsa.enc(ptxt)

    s = 2
    ctxt_ = pow(s, e, N) * ctxt % N
    ptxt_ = rsa.dec(ctxt_)

    recovered = invmod(s, N) * ptxt_ % N
    recovered = unhexlify(hex(recovered)[2:-1])
    return 'Recovered data {}'.format(loads(recovered))


def main():
    from main import Solution
    return Solution('41: Implement unpadded message recovery oracle', p41)
