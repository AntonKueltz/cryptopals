from Crypto.Cipher import AES


def detect_ECB_mode(ctxt):
    blocks = []

    for block in range(len(ctxt) / AES.block_size):
        start, end = block * AES.block_size, (block+1) * AES.block_size
        blocks.append(ctxt[start:end])

    return len(blocks) != len(set(blocks))


def detect_AES_mode(ctxt):
    if detect_ECB_mode(ctxt):
        return "Detected ECB mode"
    else:
        return "Detected CBC mode"
