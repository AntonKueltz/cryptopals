import mac
import padding
import util

master_key = util.gen_random_bytes(16)


def validate_message(msg, iv, client_mac):
    global master_key

    server_mac = mac.cbcmac(master_key, iv, msg)
    return server_mac == client_mac


def forge_mac(valid_mac, our_msg, our_id):
    # it isn't clear to me whether the key is global across all clients
    # if yes, this works. if no, then this breaks since we dont have target key
    global master_key

    zero_iv = chr(0x00) * 16
    message_block = util.xor(valid_mac, our_msg)
    forged_mac = mac.cbcmac(master_key, zero_iv, message_block)[:16]
    return forged_mac


def cbcmac_forgery():
    global master_key
    our_id = 1
    target_id = 2

    valid_msg = 'from=#{}&to=#{}&amount=#{}'.format(our_id, target_id, 1000000)
    good_iv = chr(0x00) * 16
    client_mac = mac.cbcmac(master_key, good_iv, valid_msg)

    bad_msg = 'from=#{}&to=#{}&amount=#{}'.format(target_id, our_id, 1000000)
    bad_iv = util.xor(bad_msg[:16], util.xor(valid_msg[:16], good_iv))
    assert(validate_message(bad_msg, bad_iv, client_mac))

    valid_msg = 'from=#{}&tx_list=#{}'.format(target_id, '3:5000;4:7000')
    zero_iv = chr(0x00) * 16
    valid_mac = mac.cbcmac(master_key, zero_iv, valid_msg)

    pad = padding.pkcs7(valid_msg)[len(valid_msg):]
    bad_msg = ';{}:1000000'.format(our_id)
    forged_mac = forge_mac(valid_mac, bad_msg, our_id)
    # assert(validate_message(valid_msg + pad + bad_msg, zero_iv, forged_mac))

    return 'Successfully stole 1M spacebucks!'
