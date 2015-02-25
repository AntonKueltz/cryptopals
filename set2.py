from random import randint

from Crypto.Cipher import AES

import aes_modes
import oracle
import padding
import util

master_key = util.gen_random_bytes(16)


def decrypt_CBC_Mode():
    key = "YELLOW SUBMARINE"
    iv = chr(0) * AES.block_size

    f = open('Data/10.txt')
    data = f.read().replace('\n', '').decode('base64')
    ptxt = aes_modes.AES_CBC_decrypt(data, key, iv)

    f.close()
    return ptxt


def pad_data(data):
    before, after = randint(5, 10), randint(5, 10)
    return util.gen_random_bytes(before) + data + util.gen_random_bytes(after)


def detection_oracle(data):
    key = util.gen_random_bytes(16)
    data = pad_data(data)

    ctxt = ''
    if randint(0, 1):
        print "Encrypting in ECB mode..."
        ctxt = aes_modes.AES_ECB_encrypt(data, key)
    else:
        print "Encrypting in CBC mode..."
        iv = util.gen_random_bytes(16)
        ctxt = aes_modes.AES_CBC_encrypt(data, key, iv)

    return oracle.detect_AES_mode(ctxt)


def detect_block_size(data):
    global master_key

    initial_len = len(aes_modes.AES_ECB_encrypt(data, master_key))
    cur_len = initial_len
    byts = 1

    while cur_len == initial_len:
        cur_len = len(aes_modes.AES_ECB_encrypt('A'*byts + data, master_key))
        byts += 1

    return cur_len - initial_len


def make_lookup_dict(front):
    global master_key
    lookup = {}

    for byte in range(0xFF + 1):
        v = front + chr(byte)
        k = aes_modes.AES_ECB_encrypt(v, master_key)[:AES.block_size]
        lookup[k] = v

    return lookup


def crack_block(data, block_size, i):
    byts = data[i*block_size:i*block_size+block_size]
    lookup = make_lookup_dict('A'*(block_size-1))
    ptxt = ''

    for byte in range(len(byts)):
        padlen = block_size-1 - byte
        ctxt = aes_modes.AES_ECB_encrypt('A' * padlen + byts, master_key)
        ptxt += lookup[ctxt[:block_size]][-1]

        lookup = make_lookup_dict('A' * (padlen-1) + ptxt)

    return ptxt


def break_ecb_simple(data):
    global master_key

    block_size = detect_block_size(data)
    tmp_ctxt = aes_modes.AES_ECB_encrypt('A'*block_size*4, master_key)
    oracle.detect_AES_mode(tmp_ctxt)  # discard output

    ptxt = ''
    for block in range(len(data) / block_size + 1):
        ptxt += crack_block(data, block_size, block)

    return ptxt


def profile_for(email):
    d = {}

    email = email.replace('&', '')
    email = email.replace('=', '')

    d['email'] = email
    d['uid'] = 10
    d['role'] = 'user'

    return util.encode_cookie(d)


def cut_paste_attack(ctxt):
    badblock = ctxt[AES.block_size:(2*AES.block_size)]
    newctxt = ctxt[:AES.block_size] + ctxt[(2*AES.block_size):-AES.block_size]
    return newctxt + badblock


def cut_and_paste(email):
    profile = profile_for(email)
    ctxt = aes_modes.AES_ECB_encrypt(profile, master_key)

    ctxtmod = cut_paste_attack(ctxt)
    ptxtmod = aes_modes.AES_ECB_decrypt(ctxtmod, master_key)
    return padding.validate(ptxtmod)


def bitflip(ctxt, instr):
    inject = 'dataz;admin=true'
    targetblock = ctxt[AES.block_size:(2*AES.block_size)]

    badblock = util.xor(inject, util.xor(instr, targetblock))
    start = ctxt[:AES.block_size]
    end = ctxt[2*AES.block_size:]
    return start + badblock + end


def bitflipping(instr):
    s1 = 'comment1=cooking%20MCs;userdata='
    s2 = ';comment2=%20like%20a%20pound%20of%20bacon'
    ptxt = s1 + instr.replace(';', '').replace('=', '') + s2
    iv = util.gen_random_bytes(16)

    ctxt = aes_modes.AES_CBC_encrypt(ptxt, master_key, iv)
    ctxtmod = bitflip(ctxt, instr)
    ptxtmod = aes_modes.AES_CBC_decrypt(ctxtmod, master_key, iv)
    return padding.validate(ptxtmod)
