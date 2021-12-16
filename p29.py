from binascii import hexlify
from hmac import compare_digest
from os import urandom

from main import Solution
from p28 import SHA1, sha1mac


def p29() -> str:
    msg = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound' \
          b'%20of%20bacon'
    key = urandom(16)
    auth = sha1mac(key, msg)

    msglen = len(msg) + len(key)
    dummy = b'\x00' * msglen
    s = SHA1()
    glue = s.pad(dummy)[msglen:]

    hs = []
    authval = int.from_bytes(auth, byteorder='big')
    while authval:
        hs = [int(authval & 0xffffffff)] + hs
        authval = authval >> 32

    inject = b';admin=true'
    tampered = SHA1(backdoored=True, backdoor=hs)
    forged = tampered.hash(dummy + glue + inject)

    if compare_digest(forged, sha1mac(key, msg + glue + inject)):
        return f'Message: {msg + glue + inject}\n' \
               f'MAC: {hexlify(forged).decode()}'
    else:
        return 'Message Forgery Failed'


def main() -> Solution:
    return Solution('29: Break a SHA-1 keyed MAC using length extension', p29)
