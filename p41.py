from binascii import hexlify, unhexlify
from json import dumps, loads

from main import Solution
from p39 import RSA, invmod


def p41() -> str:
    rsa = RSA()
    N, e = rsa.N, rsa.e

    ptxt = dumps({
        'time': 1356304276,
        'social': '867-00-5309',
    })
    ptxt = int(hexlify(ptxt.encode()), 16)
    ctxt = rsa.enc(ptxt)

    s = 2
    ctxt_ = pow(s, e, N) * ctxt % N
    ptxt_ = rsa.dec(ctxt_)

    recovered = invmod(s, N) * ptxt_ % N
    recovered = unhexlify(hex(recovered)[2:]).decode()
    return 'Recovered data {}'.format(loads(recovered))


def main() -> Solution:
    return Solution('41: Implement unpadded message recovery oracle', p41)
