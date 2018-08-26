from base64 import b64decode

from p02 import xor

from Crypto.Cipher import AES


def _format_64bit(n):
    byts, hx = 0, ''

    while n:
        hx += chr(n % 2**8)
        n /= 2**8
        byts += 1

    hx += chr(0) * (8 - byts)
    return hx


def aes_ctr(intxt, key, nonce=0):
    outtxt = ''
    count = 0
    cipher = AES.new(key, AES.MODE_ECB)

    while intxt:
        val = _format_64bit(nonce) + _format_64bit(count)
        stream = cipher.encrypt(val)

        outtxt += xor(intxt[:AES.block_size], stream)
        intxt = intxt[AES.block_size:]
        count += 1

    return outtxt


def p18():
    text = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX' \
           '0KSvoOLSFQ=='
    key = 'YELLOW SUBMARINE'
    return aes_ctr(b64decode(text), key)


def main():
    from main import Solution
    return Solution('18: Implement CTR, the stream cipher mode', p18)
