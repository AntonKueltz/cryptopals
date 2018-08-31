from binascii import hexlify
from hmac import compare_digest
from os import urandom

from Crypto.Cipher import AES

from p02 import xor
from p09 import pkcs7
from p11 import aes_cbc_encrypt

master_key = urandom(16)


def cbcmac(msg, iv=('\x00' * AES.block_size), key=master_key):
    ctxt = aes_cbc_encrypt(msg, key, iv)
    return ctxt[-AES.block_size:]


def validate_message(msg, iv, client_mac):
    server_mac = cbcmac(msg, iv)
    return compare_digest(server_mac, client_mac)


def forge_mac(valid_mac, our_msg):
    message_block = xor(valid_mac, pkcs7(our_msg))
    return cbcmac(message_block)


def p49():
    our_id = 1
    target_id = 2

    valid_msg = 'from=#{}&to=#{}&amount=#{}'.format(our_id, target_id, 1000000)
    good_iv = '\x00' * AES.block_size
    client_mac = cbcmac(valid_msg, good_iv)

    bad_msg = 'from=#{}&to=#{}&amount=#{}'.format(target_id, our_id, 1000000)
    bad_iv = xor(bad_msg[:AES.block_size], xor(valid_msg[:AES.block_size], good_iv))
    assert validate_message(bad_msg, bad_iv, client_mac)

    valid_msg = 'from=#{}&tx_list=#{}'.format(target_id, '3:5000;4:7000')
    valid_mac = cbcmac(valid_msg)

    bad_msg = ';{}:1000000'.format(our_id)
    forged_mac = forge_mac(valid_mac, bad_msg)
    forged_msg = pkcs7(valid_msg) + pkcs7(bad_msg)

    assert compare_digest(forged_mac, cbcmac(forged_msg))
    return 'Successfully stole 1M spacebucks! Message "{}" signed with MAC {}'.format(
        forged_msg, hexlify(forged_mac))


def main():
    from main import Solution
    return Solution('49: CBC-MAC Message Forgery', p49)
