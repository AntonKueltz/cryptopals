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
