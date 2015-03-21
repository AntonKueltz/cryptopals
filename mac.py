import sha1


class MACError(Exception):
    def __str__(self):
        return 'Expected MAC did not match computed MAC'


def sha1mac(key, msg):
    sha = sha1.SHA1()
    mac = sha.hash(key + msg)
    return mac


def authenticate(key, msg, mac):
    sha = sha1.SHA1()
    computedmac = sha.hash(key + msg)

    if computedmac != mac:
        raise MACError()

    return True


def hmac_sha1(key, msg):
    s = sha1.SHA1()

    if len(key) > s.BLOCKSIZE:
        key = s.hash(key)

    key += chr(0) * (s.BLOCKSIZE - len(key))
    o_key_pad = ''.join([chr(ord(c) ^ 0x5c) for c in key])
    i_key_pad = ''.join([chr(ord(c) ^ 0x36) for c in key])

    tmp = s.hash(i_key_pad + msg)
    inner = '0' if len(tmp) & 1 else '' + tmp
    return s.hash(o_key_pad + inner.decode('hex'))
