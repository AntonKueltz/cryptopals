from binascii import hexlify, unhexlify
from hashlib import sha1

from p39 import RSA
from p40 import kth_root


def _verify_sig(m, sig, rsa):
    hexsig = hex(pow(sig, rsa.e, rsa.N))[2:-1]
    i = hexsig.index('ff00')
    h = hexsig[i + 4:i + 44]
    return sha1(m).hexdigest() == h


def p42():
    modsize = 1024
    rsa = RSA(modsize)
    m = "hi mom"
    h = sha1(m).digest()

    mystr = '\x00\x01\xff\x00'
    mystr += h
    mystr += ((modsize / 8) - len(mystr)) * '\x00'

    forged = kth_root(int(hexlify(mystr), 16), rsa.e, rounded=True) + 1
    verified = _verify_sig(m, forged, rsa)

    assert verified
    return 'Message - {}\nSignature - {}'.format(m, forged)


def main():
    from main import Solution
    return Solution('42: Bleichenbacher\'s e=3 RSA Attack', p42)
