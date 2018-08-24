from binascii import unhexlify

from p03 import char_freq, single_byte_cipher


def p04():
    with open('Data/4.txt') as f:
        best_freq, ptxt = 0, ''

        for ctxt in f.read().split('\n'):
            raw = unhexlify(ctxt)
            txt = single_byte_cipher(raw)
            cur_freq = char_freq(txt)

            if cur_freq > best_freq:
                best_freq = cur_freq
                ptxt = txt

    return ptxt


def main():
    from main import Solution
    return Solution('4: Detect single-character XOR', p04)
