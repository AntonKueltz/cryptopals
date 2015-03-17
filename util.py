from random import randint


def hex_to_base64(hex):
    return hex.decode('hex').encode('base64')


def int_to_ascii(i):
    s = hex(i).replace('0x', '').replace('L', '')
    evenlen = ('0' if len(s) & 1 else '') + s
    return evenlen.decode('hex')


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

    for _ in xrange(byte_count):
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


def gcd(a, b):
    while b != 0:
        t = b
        b = a % b
        a = t

    return a


def mod_inv(n, mod):
    n = n % mod
    t, newt = 0, 1
    r, newr = mod, n

    while newr != 0:
        q = r / newr
        tmp1, tmp2 = t, r

        t = newt
        newt = tmp1 - q * newt
        r = newr
        newr = tmp2 - q * newr

    if r > 1:
        return 0
    elif t < 0:
        return t + mod
    else:
        return t


def kth_root(n, k):
    bits = len(bin(n)[2:])
    mn, mx = (2**(bits / k)), (2**(bits / k + 1))
    mid = (mx + mn) / 2
    guess = mid**k

    while guess != n:
        if mn > mx or mn**k > n or mx**k < n:
            return None
        elif n > guess:
            mn = mid
        else:
            mx = mid

        mid = (mx + mn) / 2
        guess = mid**k

    return mid
