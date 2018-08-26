from base64 import b64decode
from os import urandom

from p18 import aes_ctr


def _char_val(char):
    common_letters = 'etaoinshr'
    # weigh letters higher than special chars and digits
    if chr(char) in common_letters:
        return 5
    elif char >= ord('a') and char <= ord('z') or chr(char) == ' ':
        return 3
    elif char >= ord('A') and char <= ord('Z') or chr(char) in ',.':
        return 1
    else:
        return -1


def get_key(byts):
    best_key, count = 0, 0

    for key_byte in range(0xff + 1):
        score = 0

        for b in byts:
            if b == '':
                continue
            score += _char_val(ord(b) ^ key_byte)

        if score > count:
            best_key = key_byte
            count = score

    return chr(best_key)


def p19():
    key = urandom(16)
    ctxts = []

    with open('Data/19.txt') as f:
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
    return Solution('19: Break fixed-nonce CTR mode using substitions', p19)
