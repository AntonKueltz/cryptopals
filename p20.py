from base64 import b64decode
from os import urandom

from p18 import aes_ctr
from p19 import get_key


def p20() -> bytes:
    key = urandom(16)
    ctxts = []

    with open('Data/20.txt', 'rb') as f:
        for line in f.readlines():
            ptxt = b64decode(line)
            ctxts.append(aes_ctr(ptxt, key, 0))

    keystream = b''
    for i in range(min(map(len, ctxts))):
        keystream += get_key([c[i] for c in ctxts])

    ptxt = []
    for ctxt in ctxts:
        raw = [c ^ k for (c, k) in zip(ctxt, keystream)]
        ptxt.append(bytes(raw))

    return b'\n'.join(ptxt)


def main():
    from main import Solution
    return Solution('20: Break fixed-nonce CTR statistically', p20)
