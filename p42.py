from binascii import hexlify
from hashlib import sha1

from main import Solution
from p39 import RSA
from p40 import kth_root


def _verify_sig(m: bytes, sig: int, rsa: RSA) -> bool:
    hexsig = hex(pow(sig, rsa.e, rsa.N))[2:]
    i = hexsig.index('ff00')
    h = hexsig[i + 4:i + 44]
    return sha1(m).hexdigest() == h


def p42():
    modsize = 1024
    rsa = RSA(modsize)
    m = b'hi mom'
    h = sha1(m).digest()

    mystr = b'\x00\x01\xff\x00'
    mystr += h
    mystr += ((modsize // 8) - len(mystr)) * b'\x00'

    forged = kth_root(int(hexlify(mystr), 16), rsa.e, rounded=True) + 1
    verified = _verify_sig(m, forged, rsa)

    assert verified
    return f'Message - {m.decode()}\nSignature - {forged}'


def main() -> Solution:
    return Solution('42: Bleichenbacher\'s e=3 RSA Attack', p42)
