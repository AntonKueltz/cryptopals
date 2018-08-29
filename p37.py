from hmac import new as new_hmac
from hashlib import sha256
from json import loads

from p33 import DiffieHellman
from p36 import Server, start_server

from requests import ConnectionError, post


def p37():
    server = Server()
    base_url = 'http://0.0.0.0:8080/login'

    N = DiffieHellman.default_p
    g, k = 2, 3
    I, P = 'foo@bar.com', 'abhorrentaardvark'
    A = 0  # same as N, N^2 etc since they're in the same equivalence class mod N

    print 'Sending I and A to server...'
    try:
        args = '?I={}&A={}'.format(I, A)
        response = post(base_url + args)
        response_content = loads(response.content)
    except ConnectionError:
        response_content = server.get_client_ids(I, A)

    salt, B = response_content.get('salt'), response_content.get('B')
    print 'Server responded with salt = {} and B = {}...'.format(salt, str(B)[:20])

    K = sha256('0').hexdigest()
    print 'Client computed K = {}...'.format(K[:20])
    client_hmac = new_hmac(K, str(salt), sha256).hexdigest()

    print 'Sending HMAC to server...'
    try:
        args = '?hmac={}'.format(client_hmac)
        response = post(base_url + args)
    except ConnectionError:
        response = server.check_hmac(client_hmac)

    if response.status_code != 200:
        return 'Server responded with "403 Forbidden"'

    return 'Server responded with "200 OK"'


def main():
    from main import Solution
    return Solution('37: Break SRP with a zero key', p37)


# BELOW CODE RUNS THE WEBSERVER THAT HANDLES THE POST TO /login
if __name__ == '__main__':
    start_server()
