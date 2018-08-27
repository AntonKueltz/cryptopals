from hmac import compare_digest
from os import urandom

from p28 import SHA1, sha1mac


def p29():
    msg = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound' \
          '%20of%20bacon'
    key = urandom(16)
    auth = sha1mac(key, msg)

    msglen = len(msg) + len(key)
    dummy = '\x00' * msglen
    s = SHA1()
    glue = s.pad(dummy)[msglen:]

    hs = []
    authval = int(auth, 16)
    while authval:
        hs = [int(authval & 0xffffffff)] + hs
        authval = authval >> 32

    inject = ';admin=true'
    tampered = SHA1(backdoored=True, backdoor=hs)
    forged = tampered.hash(dummy + glue + inject)

    if compare_digest(forged, sha1mac(key, msg + glue + inject)):
        return 'Message: {}\nMAC: {}'.format(msg + glue + inject, forged)
    else:
        return 'Message Forgery Failed'


def main():
    from main import Solution
    return Solution('29: Break a SHA-1 keyed MAC using length extension', p29)
