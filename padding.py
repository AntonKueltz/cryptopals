from Crypto.Cipher import AES


class PaddingError(Exception):
    def __init__(self, val):
        self.val = val

    def __str__(self):
        return "Last block {} not padded per PKCS#7".format(
            self.val[-AES.block_size:])


def pkcs7(data, block_size=AES.block_size):
    bytes_to_pad = block_size - (len(data) % block_size)

    for _ in range(bytes_to_pad):
        data += chr(bytes_to_pad)
    return data


def validate(ptxt):
    padval = ord(ptxt[-1])

    if padval > 16 or padval <= 0:
        raise PaddingError(ptxt)

    for i in range(padval):
        if ord(ptxt[-(i+1)]) != padval:
            raise PaddingError(ptxt)

    return ptxt[:-padval]
