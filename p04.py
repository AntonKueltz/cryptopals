from binascii import unhexlify

from main import Solution
from p03 import char_freq, single_byte_cipher


def p04() -> bytes:
    with open('Data/4.txt', 'rb') as f:
        best_freq, ptxt = 0, b''

        for ctxt in f.read().split(b'\n'):
            raw = unhexlify(ctxt)
            txt = single_byte_cipher(raw)
            cur_freq = char_freq(txt)

            if cur_freq > best_freq:
                best_freq = cur_freq
                ptxt = txt

    return ptxt


def main() -> Solution:
    return Solution('4: Detect single-character XOR', p04)
