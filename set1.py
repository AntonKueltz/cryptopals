import aes_modes
import oracle
import util

def break_single_byte(ctxt):
    freqs = []

    for key in range(0xFF + 1):
        chars = []
        for c in ctxt: chars.append(chr(ord(c) ^ key))
        freqs.append(util.char_freq(chars))

    return freqs.index(max(freqs))

def single_byte_cipher(ctxt):
    key = chr(break_single_byte(ctxt))
    return util.repeating_key_xor(ctxt, key)

def detect_single_byte():
    f = open('Data/4.txt')
    best_freq, ptxt = 0, ''

    for ctxt in f.read().split('\n'):
        raw = ctxt.decode('hex')
        txt = single_byte_cipher(raw)
        cur_freq = util.char_freq(txt)

        if cur_freq > best_freq:
            best_freq = cur_freq
            ptxt = txt

    f.close()
    return ptxt

def best_key_lengths(data):
    avg_dist = []

    for ksize in range(2, 41):
        b1, b2, b3, b4 = data[:ksize], data[ksize:2*ksize], \
            data[2*ksize: 3*ksize], data[3*ksize:4*ksize]
        dists, blocks = [], [b1, b2, b3, b4]

        for i in range(len(blocks)-2):
            for j in range(i+1, len(blocks)-1):
                dists.append(util.hamming(blocks[i], blocks[j]) / float(ksize))

        avg_dist.append((sum(dists) / len(dists), ksize))

    return sorted(avg_dist)[:3]

def break_repeating_key():
    f = open('Data/6.txt')
    data = f.read().replace('\n', '').decode('base64')

    keylens = best_key_lengths(data)
    best_freq, ptxt = 0, ''

    for _, keylen in keylens:
        key = ''
        blocks = [''] * keylen
        for i, c in enumerate(data): blocks[i % keylen] += c

        for block in blocks:
            key += chr(break_single_byte(block))

        txt = util.repeating_key_xor(data, key)
        cur_freq = util.char_freq(txt)

        if cur_freq > best_freq:
            best_freq = cur_freq
            ptxt = txt

    f.close()
    return ptxt

def decrypt_AES_ECB():
    f = open('Data/7.txt')
    data = f.read().replace('\n', '').decode('base64')
    key = 'YELLOW SUBMARINE'

    return aes_modes.AES_ECB_decrypt(data, key)

def detect_ECB():
    f = open('Data/8.txt')
    ctxts = [txt.decode('hex') for txt in f.read().split('\n')]

    for ctxt in ctxts:
        if oracle.detect_ECB_mode(ctxt):
            return ctxt.encode('hex')

    return None
