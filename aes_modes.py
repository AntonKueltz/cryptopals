from Crypto.Cipher import AES

import padding
import util


def AES_ECB_encrypt(ptxt, key):
    ctxt = ''
    cipher = AES.new(key, AES.MODE_ECB)
    padded = padding.pkcs7(ptxt)

    for block in range(len(padded) / AES.block_size):
        start, end = block * AES.block_size, (block+1) * AES.block_size
        ctxt += cipher.encrypt(padded[start:end])

    return ctxt


def AES_ECB_decrypt(ctxt, key):
    ptxt = ''
    cipher = AES.new(key, AES.MODE_ECB)

    for block in range(len(ctxt) / AES.block_size):
        start, end = block * AES.block_size, (block+1) * AES.block_size
        ptxt += cipher.decrypt(ctxt[start:end])

    return ptxt


def AES_CBC_encrypt(ptxt, key, iv):
    ctxt = ''
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    padded = padding.pkcs7(ptxt)

    for block in range(len(padded) / AES.block_size):
        start, end = block * AES.block_size, (block+1) * AES.block_size
        cur_block = padded[start:end]

        tmp = util.xor(prev_block, cur_block)
        ctxtblock = cipher.encrypt(tmp)
        ctxt += ctxtblock

        prev_block = ctxtblock

    return ctxt


def AES_CBC_decrypt(ctxt, key, iv):
    ptxt = ''
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = iv

    for block in range(len(ctxt) / AES.block_size):
        start, end = block * AES.block_size, (block+1) * AES.block_size
        cur_block = ctxt[start:end]

        tmp = cipher.decrypt(cur_block)
        ptxt += util.xor(prev_block, tmp)

        prev_block = cur_block

    return ptxt


def AES_CTR(intxt, key, nonce):
    outtxt = ''
    count = 0
    cipher = AES.new(key, AES.MODE_ECB)

    while intxt:
        val = format_64bit(nonce) + format_64bit(count)
        mask = cipher.encrypt(val)

        outtxt += util.xor(intxt[:AES.block_size], mask)
        intxt = intxt[AES.block_size:]
        count += 1

    return outtxt


def format_64bit(n):
    byts, hx = 0, ''

    while n:
        hx += chr(n % 2**8)
        n /= 2**8
        byts += 1

    hx += chr(0) * (8 - byts)
    return hx
