from base64 import b64decode
from os import urandom
from typing import List, Optional

from main import Solution
from p18 import aes_ctr


def _char_val(char: int) -> int:
    common_letters = 'etaoinshr'
    # weigh letters higher than special chars and digits
    if chr(char) in common_letters:
        return 5
    elif ord('a') <= char <= ord('z') or chr(char) == ' ':
        return 3
    elif ord('A') <= char <= ord('Z') or chr(char) in ',.':
        return 1
    else:
        return -1


def get_key(byts: List[Optional[int]]) -> bytes:
    best_key, count = 0, 0

    for key_byte in range(0xff + 1):
        score = 0

        for b in byts:
            if b is None:
                continue
            score += _char_val(b ^ key_byte)

        if score > count:
            best_key = key_byte
            count = score

    return bytes([best_key])


def p19() -> bytes:
    key = urandom(16)
    ctxts = []

    with open('Data/19.txt', 'rb') as f:
        for line in f.readlines():
            ptxt = b64decode(line)
            ctxts.append(aes_ctr(ptxt, key, 0))

    keystream = b''
    for i in range(max(map(len, ctxts))):
        index_bytes = [(c[i] if i < len(c) else None) for c in ctxts]
        keystream += get_key(index_bytes)

    ptxt = []
    for ctxt in ctxts:
        raw = [c ^ k for (c, k) in zip(ctxt, keystream)]
        ptxt.append(bytes(raw))

    return b'\n'.join(ptxt)


def main() -> Solution:
    return Solution('19: Break fixed-nonce CTR mode using substitutions', p19)
