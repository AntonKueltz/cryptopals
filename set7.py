import operator

import mac
import oracle
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

    return 'Successfully stole 1M spacebucks!'


def cbcmac_collision():
    key, iv = 'YELLOW SUBMARINE', chr(0x00) * 16
    str1 = 'alert(\'MZA who was that?\');\n'
    target_hash = mac.cbcmac(key, iv, str1)

    str2 = 'alert(\'Ayo, the Wu is back!\');//'
    intermediate_hash = mac.cbcmac(key, iv, str2)

    block0 = chr(0x10) * 16
    block1 = util.xor(intermediate_hash, str1[:16])
    block2 = str1[16:]
    valid_snippet = str2 + block0 + block1 + block2
    collision_hash = mac.cbcmac(key, iv, valid_snippet)

    collision = collision_hash == target_hash
    return 'Created valid code snippet!' if collision else 'Incorrect hash :('


def calc_padding(content):
    padding = 'ABCDEFGHIJKLMNOP'
    curlen = oracle.detect_compressed_size(content)
    i = 0

    while oracle.detect_compressed_size(content + padding[:i]) == curlen:
        i += 1

    return padding[:i-1]


def compression_side_channel():
    content = 'sessionid='
    shortest = ['']

    while True:
        minlen = 1000000
        round_shortest = []
        padding = calc_padding(content + shortest[0])

        for guess in map(chr, range(0xff + 1)):
            for cand in shortest:
                intxt = padding + content + cand + guess
                length = oracle.detect_compressed_size(intxt)

                if length == minlen:
                    round_shortest.append(cand + guess)
                elif length < minlen:
                    round_shortest = [cand + guess]
                    minlen = length

        shortest = round_shortest[:]

        if len(shortest) == 1 and shortest[0][-1] == '\n':
            return shortest[0][:-1]


def rc4_bit_biases():
    cookie_len = len(oracle.rc4_encryption_oracle(''))
    z16, z32 = 15, 31
    z16_bias, z32_bias = 0xf0, 0xe0

    for i in range((cookie_len / 2) + 1):
        z16_map, z32_map = {}, {}

        for j in xrange(2**24):
            # if j % 1000 == 0:
            #     print j
            offset = z16 - i
            request = 'A' * offset
            result = oracle.rc4_encryption_oracle(request)

            try:
                z16_map[result[z16]] += 1
            except KeyError:
                z16_map[result[z16]] = 1
            try:
                z32_map[result[z32]] += 1
            except KeyError:
                z32_map[result[z32]] = 1

        z16_char = max(z16_map.items(), key=operator.itemgetter(1))[0]
        z32_char = max(z32_map.items(), key=operator.itemgetter(1))[0]
        print chr(ord(z16_char) ^ z16_bias), chr(ord(z32_char) ^ z32_bias)
