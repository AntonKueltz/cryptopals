from Crypto.Cipher import AES
from Crypto.Random import random


class PaddingError(Exception):
    def __init__(self, val, version):
        self.val = val
        self.version = version

    def __str__(self):
        if self.version == 1.5:
            return self.val

        elif self.version == 7:
            return "Last block {} not padded per PKCS#7".format(
                self.val[-AES.block_size:])


def pkcs7(data, block_size=AES.block_size):
    bytes_to_pad = block_size - (len(data) % block_size)

    for _ in range(bytes_to_pad):
        data += chr(bytes_to_pad)
    return data


def pkcs1_5(m, mod_bytes):
    padlen = mod_bytes - 3 - len(m)
    pad = chr(0x00) + chr(0x02)

    if padlen < 8:
        raise PaddingError("Not enough bytes for padding", 1.5)

    for _ in range(padlen):
        pad += chr(random.randint(1, 255))

    pad += chr(0x00)
    assert(len(pad + m) == mod_bytes)
    return pad + m


def validate(ptxt):
    padval = ord(ptxt[-1])

    if padval > 16 or padval <= 0:
        raise PaddingError(ptxt, 7)

    for i in range(padval):
        if ord(ptxt[-(i+1)]) != padval:
            raise PaddingError(ptxt, 7)

    return ptxt[:-padval]


def validate1_5(ptxt):
    if ptxt[0] != chr(0x02):
        raise PaddingError('First bytes not 0x0002', 1.5)

    try:
        idx = ptxt[1:].index(chr(0x00))
    except:
        raise PaddingError('No 0x00 delimiter found!', 1.5)

    return ptxt[2+idx:]
