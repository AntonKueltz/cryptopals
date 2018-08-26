from base64 import b64decode
from os import urandom

from p18 import aes_ctr
from p19 import get_key


def p20():
    key = urandom(16)
    ctxts = []

    with open('Data/20.txt') as f:
        for line in f.readlines():
            ptxt = b64decode(line)
            ctxts.append(aes_ctr(ptxt, key, 0))

    keystream = ''
    for i in range(max(map(len, ctxts))):
        keystream += get_key([(c[i] if i < len(c) else '') for c in ctxts])

    ptxt = ''
    for ctxt in ctxts:
        raw = [chr(ord(c) ^ ord(k)) for (c, k) in zip(ctxt, keystream)]
        ptxt += ''.join(raw) + '\n'

    return ptxt[:-1]


def main():
    from main import Solution
    return Solution('20: Break fixed-nonce CTR statistically', p20)
