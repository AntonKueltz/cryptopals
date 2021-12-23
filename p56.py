from base64 import b64decode
from operator import itemgetter
from os import urandom
from typing import Dict

from main import Solution

from Crypto.Cipher import ARC4

cookie = b64decode('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')


def _rc4_encryption_oracle(request: bytes) -> bytes:
    fresh_key = urandom(16)
    cipher = ARC4.new(fresh_key)
    return cipher.encrypt(request + cookie)


def p56() -> str:
    cookie_len = len(_rc4_encryption_oracle(b''))
    z16, z32 = 15, 31
    z16_bias, z32_bias = 0xf0, 0xe0
    plaintext = ['?'] * cookie_len

    for i in range((cookie_len // 2) + 1):
        offset = z16 - i
        request = b'A' * offset
        z16_map: Dict[int, int] = {}
        z32_map: Dict[int, int] = {}
        check_z32 = z32 < (len(request) + cookie_len)

        for j in range(2**24):
            result = _rc4_encryption_oracle(request)

            try:
                z16_map[result[z16]] += 1
            except KeyError:
                z16_map[result[z16]] = 1

            if check_z32:
                try:
                    z32_map[result[z32]] += 1
                except KeyError:
                    z32_map[result[z32]] = 1

        z16_char = max(z16_map.items(), key=itemgetter(1))[0]
        plaintext[z16 - offset] = chr(z16_char ^ z16_bias)

        if check_z32:
            z32_char = max(z32_map.items(), key=itemgetter(1))[0]
            plaintext[z32 - offset] = chr(z32_char ^ z32_bias)

        print(''.join(plaintext))

    return f'Recovered message "{"".join(plaintext)}"'


def main() -> Solution:
    return Solution('56: RC4 Single-Byte Biases', p56)
