import random
import time

from Crypto.Cipher import AES

import aes_modes
import padding
import prng
import util


def untemper(mt_out):
    y = mt_out

    tmp1 = y & 0xFFFFC000
    tmp2 = (((y << 18) ^ y) >> 18) & 0xFFFFFFFF
    y = tmp1 | tmp2

    tmp1 = y & 0x7FFF
    tmp2 = ((y << 15) & 4022730752) ^ y
    y = tmp1 | tmp2

    tmp1 = y & 0x7F
    tmp2 = (((tmp1 << 7) & 2636928640) ^ y) & 0x3F80
    tmp3 = (((tmp2 << 7) & 2636928640) ^ y) & 0x1FC000
    tmp4 = (((tmp3 << 7) & 2636928640) ^ y) & 0xFE00000
    tmp5 = (((tmp4 << 7) & 2636928640) ^ y) & 0xF0000000
    y = tmp1 | tmp2 | tmp3 | tmp4 | tmp5

    tmp1 = y & 0xFFE00000
    tmp2 = (((y << 11) ^ y) & 0xFFE00000) >> 11
    tmp3 = ((tmp2 >> 11) ^ y) & 0x3FF
    y = tmp1 | tmp2 | tmp3

    return y


def clone_mt19937():
    mt = prng.MersenneTwister(int(time.time()))
    output = []

    for _ in range(624):
        output.append(mt.extract())

    untempered = map(untemper, output)
    clone = prng.MersenneTwister(0)
    clone.MT = untempered
    cloned_output = []

    for _ in range(624):
        cloned_output.append(clone.extract())
        output.append(mt.extract())

    equal = cloned_output == output[624:]
    return 'Clone Successful' if equal else 'Clone Unsuccessful :('


def crack_mt19937_seed(runlegit=False):
    if runlegit:
        low, high = 40, 100
    else:
        low, high = 1, 5

    wait = random.randint(low, high)
    time.sleep(wait)

    seed = int(time.time())
    print 'Seed is {}'.format(seed)
    mt = prng.MersenneTwister(seed)

    wait = random.randint(low, high)
    time.sleep(wait)
    observed_out = mt.extract()

    guess = 0
    guess_seed = int(time.time()) + 1

    while guess != observed_out:
        guess_seed -= 1
        mt_ = prng.MersenneTwister(guess_seed)
        guess = mt_.extract()

    return guess_seed


def prng_output():
    mt = prng.MersenneTwister(0)
    out = ''
    for _ in range(5):
        out += str(mt.extract()) + ' '
    return out[:-1]


def break_cbc(ctxt, key, iv):
    ptxt = ''
    prevblock = iv

    for block in range(len(ctxt) / AES.block_size):
        ctxtblock = ctxt[block*AES.block_size:(block+1)*AES.block_size]
        cipherout = ''

        for cur_pad_byte in range(1, AES.block_size+1):
            mask = ''.join([chr(cur_pad_byte ^ ord(s)) for s in cipherout])

            for byt in range(0xFF+1):
                validpad = True
                block = 'A' * (AES.block_size-len(mask)-1) + chr(byt) + mask

                # server would be doing this
                try:
                    out = aes_modes.AES_CBC_decrypt(ctxtblock, key, block)
                    padding.validate(out)
                except:
                    validpad = False

                # back to client now
                if validpad:
                    cipherout = chr(byt ^ cur_pad_byte) + cipherout
                    break

        ptxt += util.xor(prevblock, cipherout)
        prevblock = ctxtblock

    return ptxt


def cbc_oracle_attack():
    strs = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB'
        '1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]

    key, iv = util.gen_random_bytes(16), util.gen_random_bytes(16)
    ptxt = random.choice(strs).decode('base64')

    ctxt = aes_modes.AES_CBC_encrypt(ptxt, key, iv)
    ptxt = break_cbc(ctxt, key, iv)

    return ptxt


def char_val(char):
    # weigh letters higher than special chars and digits
    if char >= ord('a') and char <= ord('z'):
        return 3
    elif char >= ord('A') and char <= ord('Z'):
        return 2
    elif char >= ord('0') and char <= ord('9'):
        return 1
    elif chr(char) in ' ,.!?:;':
        return 1
    else:
        return 0


def break_byte(byts):
    best_key, count = 0, 0

    for key_byte in range(0xFF+1):
        score = 0

        for b in byts:
            if b == '':
                continue
            score += char_val(ord(b) ^ key_byte)

        if score > count:
            best_key = key_byte
            count = score

    return chr(best_key ^ ord(byts[0]))


def break_fixed_nonce():
    f = open('Data/19.txt')
    key = util.gen_random_bytes(16)
    ctxts = []

    for line in f.readlines():
        ptxt = line.decode('base64')
        ctxts.append(aes_modes.AES_CTR(ptxt, key, 0))

    ptxt1 = ''
    for i in range(len(ctxts[0])):
        ptxt1 += break_byte([(c[i] if i < len(c) else '') for c in ctxts])

    f.close()
    return ptxt1
