import random
import requests
import time

from Crypto.Cipher import AES

import aes_modes
import mac
import server
import sha1
import util


class ASCIIError(Exception):
    def __init__(self, ptxt):
        self.msg = ptxt

    def __str__(self):
        return 'Malformed txt: {}'.format(self.msg)


def edit_ctxt(ctxt, key, nonce, offset, newtext):
    byts = len(newtext)
    start_block = offset / AES.block_size
    end_block = (offset + byts - 1) / AES.block_size

    cipher = AES.new(key, AES.MODE_ECB)
    keybytes = ''

    for block in range(start_block, end_block+1):
        intxt = aes_modes.format_64bit(nonce) + aes_modes.format_64bit(block)
        keybytes += cipher.encrypt(intxt)

    keyoffset = offset % AES.block_size
    keybytes = keybytes[keyoffset:keyoffset + byts]
    edited_ctxt = util.xor(newtext, keybytes)

    return ctxt[:offset] + edited_ctxt + ctxt[offset+byts:]


def read_write_CTR():
    f = open('Data/25.txt')
    data = f.read().replace('\n', '').decode('base64')
    key = 'YELLOW SUBMARINE'
    ptxt = aes_modes.AES_ECB_decrypt(data, key)

    key, nonce = util.gen_random_bytes(16), random.randint(0, 2**32-1)
    ctxt = aes_modes.AES_CTR(ptxt, key, nonce)

    newtext = 'A' * len(ctxt)
    edited = edit_ctxt(ctxt, key, nonce, 0, newtext)
    return util.xor(util.xor(edited, ctxt), newtext)


def bitflip(ctxt, instr):
    inject = 'dataz;admin=true'
    targetblock = ctxt[(2*AES.block_size):(3*AES.block_size)]
    keybytes = util.xor(instr, targetblock)

    badblock = util.xor(inject, keybytes)
    start = ctxt[:(2*AES.block_size)]
    end = ctxt[(3*AES.block_size):]
    return start + badblock + end


def bitflipping_CTR(instr):
    s1 = 'comment1=cooking%20MCs;userdata='
    s2 = ';comment2=%20like%20a%20pound%20of%20bacon'
    ptxt = s1 + instr.replace(';', '').replace('=', '') + s2
    key, nonce = util.gen_random_bytes(16), random.randint(0, 2**32-1)

    ctxt = aes_modes.AES_CTR(ptxt, key, nonce)
    ctxtmod = bitflip(ctxt, instr)
    ptxtmod = aes_modes.AES_CTR(ctxtmod, key, nonce)
    return ptxtmod


def check_ascii_compliant(msg):
    for c in msg:
        if ord(c) < 32:
            raise ASCIIError(msg)


def key_as_iv():
    key = util.gen_random_bytes(16)
    print 'The key is {}'.format(key.encode('hex'))
    msg = 'Super secret message unfortunately encrypted in a bad manner'

    ctxt = aes_modes.AES_CBC_encrypt(msg, key, key)
    c1 = ctxt[:AES.block_size]
    zeros = chr(0) * AES.block_size
    ctxt = c1 + zeros + c1 + ctxt[3*AES.block_size:]

    try:
        return check_ascii_compliant(aes_modes.AES_CBC_decrypt(ctxt, key, key))
    except ASCIIError as e:
        start = len('Malformed txt: ')
        ptxt = str(e)[start:]
        p1, p3 = ptxt[:AES.block_size], ptxt[2*AES.block_size:3*AES.block_size]
        return 'Recovered ' + util.xor(p1, p3).encode('hex')


def length_extension():
    msg = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound' \
          '%20of%20bacon'
    key = util.gen_random_bytes(16)
    auth = mac.sha1mac(key, msg)

    msglen = len(msg) + len(key)
    dummy = chr(0x00) * msglen
    s = sha1.SHA1()
    glue = s.pad(dummy)[msglen:]

    hs = []
    authval = int(auth, 16)
    while authval:
        hs = [int(authval & 0xFFFFFFFF)] + hs
        authval = authval >> 32

    inject = ';admin=true'
    tampered = sha1.SHA1(backdoored=True, backdoor=hs)
    forged = tampered.hash(dummy + glue + inject)

    try:
        if mac.authenticate(key, msg + glue + inject, forged):
            return 'Successfully Forged Message!\n' \
                   'Message: {}\nMAC: {}'.format(msg + glue + inject, forged)
        else:
            return 'Message Forgery Failed'
    except:
        return 'Message Forgery Failed'


def sha1mac():
    msg = 'Some super secret thing I dont want to share'
    key = util.gen_random_bytes(16)
    auth = mac.sha1mac(key, msg)
    testpassed = 0

    try:
        assert(mac.authenticate(key, msg, auth) == True)
        testpassed += 1
        print 'Correct MAC accepted'
    except:
        print 'Correct MAC erroneously rejected'
    try:
        badauth = mac.sha1mac(util.gen_random_bytes(16), msg)
        assert(mac.authenticate(key, msg, badauth) == True)
        print 'Tampered MAC erroneously accepted'
    except:
        testpassed += 1
        print 'Tampered MAC rejected'
    try:
        badmsg = 'I didnt write this'
        assert(mac.authenticate(key, badmsg, auth) == True)
        print 'Tampered message erroneously accepted'
    except:
        testpassed += 1
        print 'Tampered message rejected'

    if testpassed == 3:
        return 'All Tests Passed!'
    else:
        return 'Not All Tests Passed :('


def hmac_sha1_timing_leak(file, stime):
    key = 'YELLOW SUBMARINE'
    expected = mac.hmac_sha1(key, file)
    known = ''
    print 'Expected: {}'.format(expected)

    while len(known) < len(expected):
        print known
        unknown = (len(expected) - len(known) - 2) * '0'
        longest, best = 0.0, ''

        for byt in range(0, 0xFF+1):
            sig = known + util.int_to_hexstr(byt) + unknown
            url = 'http://0.0.0.0:8080/hmac?file={}&sig={}&stime={}'.format(
                file, sig, stime)

            start = time.time()
            req = requests.post(url)
            end = time.time()

            runtime = end - start
            if runtime > longest:
                longest = runtime
                best = util.int_to_hexstr(byt)

        known += best

    equal = known == expected
    return 'HMAC Successfully Broken!' if equal else 'HMAC Was Not Broken :('
