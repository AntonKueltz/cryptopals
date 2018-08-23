from zlib import compress

from Crypto.Cipher import AES, ARC4

from aes_modes import AES_CBC_encrypt
from util import gen_random_bytes


def detect_ECB_mode(ctxt):
    blocks = []

    for block in range(len(ctxt) / AES.block_size):
        start, end = block * AES.block_size, (block+1) * AES.block_size
        blocks.append(ctxt[start:end])

    return len(blocks) != len(set(blocks))


def detect_AES_mode(ctxt):
    if detect_ECB_mode(ctxt):
        return "Detected ECB mode"
    else:
        return "Detected CBC mode"


def detect_compressed_size(ptxt):
    key, iv = gen_random_bytes(16), gen_random_bytes(16)
    request = 'POST / HTTP/1.1\n' \
              'Host: hapless.com\n' \
              'Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE' \
              '=\n' \
              'Content-Length: {}\n{}'.format(len(ptxt), ptxt)

    ctxt = AES_CBC_encrypt(compress(request), key, iv)
    return len(ctxt)


def rc4_encryption_oracle(request):
    cookie = 'QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F'.decode('base64')
    fresh_key = gen_random_bytes(16)

    cipher = ARC4.new(fresh_key)
    return cipher.encrypt(request + cookie)
