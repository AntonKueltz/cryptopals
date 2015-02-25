from random import randint


def hex_to_base64(hex):
    return hex.decode('hex').encode('base64')


def xor(buf1, buf2):
    result = ""
    for b1, b2 in zip(buf1, buf2):
        result += chr(ord(b1) ^ ord(b2))
    return result


def repeating_key_xor(intxt, key):
    outtxt = ""

    for i, c in enumerate(intxt):
        outtxt += chr(ord(c) ^ ord(key[i % len(key)]))

    return outtxt


def char_freq(chars):
    freq = 0
    most_freq_letters = 'etaoinhs'

    for c in chars:
        if c in most_freq_letters:
            freq += 1

    return freq


def hamming(s1, s2):
    dist = 0

    for c1, c2 in zip(s1, s2):
        diff = ord(c1) ^ ord(c2)
        dist += sum([1 for b in bin(diff) if b == '1'])

    return dist


def gen_random_bytes(byte_count):
    byts = ''

    for _ in range(byte_count):
        byts += chr(randint(0, 127))

    return byts


def parse_cookie(cookie):
    d = {}

    for var in cookie.split('&'):
        tmp = var.split('=')

        try:
            d[tmp[0]] = tmp[1]
        except:
            print "Malformed Cookie!"
            return None

    return d


def encode_cookie(dic):
    encoded = ''

    for k in ['email', 'uid', 'role']:
        encoded += (k + '=' + str(dic[k]))
        encoded += '&'

    return encoded[:-1]  # omit last '&'


def mod_exp(base, ex, mod):
    result = 1
    base = base % mod

    while ex > 0:
        if ex % 2:
            result = (result * base) % mod
        ex = ex >> 1
        base = (base * base) % mod

    return result