from _sodium import ffi, lib

crypto_secretbox_NONCEBYTES = lib.crypto_secretbox_noncebytes()
crypto_secretbox_KEYBYTES = lib.crypto_secretbox_keybytes()
crypto_secretbox_MACBYTES = lib.crypto_secretbox_macbytes()
crypto_box_NONCEBYTES = lib.crypto_box_noncebytes()
crypto_box_PUBLICKEYBYTES = lib.crypto_box_publickeybytes()
crypto_box_SECRETKEYBYTES = lib.crypto_box_secretkeybytes()
crypto_box_MACBYTES = lib.crypto_box_macbytes()
crypto_sign_PUBLICKEYBYTES = lib.crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = lib.crypto_sign_secretkeybytes()
crypto_sign_BYTES = lib.crypto_sign_bytes()

def random_bytes(bytes_len):
    buf = ffi.new('uint8_t[]', bytes_len)
    lib.randombytes_buf(buf, bytes_len)
    return bytes(buf)

def crypto_secretbox_easy(m, n, k):
    if len(n) != crypto_secretbox_NONCEBYTES:
        raise Exception('Nonce is {} bytes, expected {} bytes'.format(len(n), crypto_secretbox_NONCEBYTES))

    if len(k) != crypto_secretbox_KEYBYTES:
        raise Exception('Key is {} bytes, expected {} bytes'.format(len(k), crypto_secretbox_KEYBYTES))

    buf = ffi.new('unsigned char[]', crypto_secretbox_MACBYTES + len(m))
    lib.crypto_secretbox_easy(buf, m, len(m), n, k)
    return bytes(buf)

def crypto_secretbox_open_easy(c, n, k): 
    if len(n) != crypto_secretbox_NONCEBYTES:
        raise Exception('Nonce is {} bytes, expected {} bytes'.format(len(n), crypto_secretbox_NONCEBYTES))

    if len(k) != crypto_secretbox_KEYBYTES:
        raise Exception('Key is {} bytes, expected {} bytes'.format(len(k), crypto_secretbox_KEYBYTES))

    buf = ffi.new('unsigned char[]', len(c) - crypto_secretbox_MACBYTES)
    ret = lib.crypto_secretbox_open_easy(buf, c, len(c), n, k)
    if ret != 0:
        raise Exception('Failed to verify ciphertext')

    return bytes(buf)

def crypto_box_keypair():
    pk = ffi.new('unsigned char[]', crypto_box_PUBLICKEYBYTES)
    sk = ffi.new('unsigned char[]', crypto_box_SECRETKEYBYTES)
    lib.crypto_box_keypair(pk, sk)
    return (bytes(pk), bytes(sk))

def crypto_box_easy(m, n, pk, sk):
    if len(n) != crypto_box_NONCEBYTES:
        raise Exception('Nonce is {} bytes, expected {} bytes'.format(len(n), crypto_box_NONCEBYTES))

    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise Exception('Public key is {} bytes, expected {} bytes'.format(len(pk), crypto_box_PUBLICKEYBYTES))

    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise Exception('Secret key is {} bytes, expected {} bytes'.format(len(sk), crypto_box_SECRETKEYBYTES))

    buf = ffi.new('unsigned char[]', crypto_box_MACBYTES + len(m))
    lib.crypto_box_easy(buf, m, len(m), n, pk, sk)
    return bytes(buf)

def crypto_box_open_easy(c, n, pk, sk):
    if len(n) != crypto_box_NONCEBYTES:
        raise Exception('Nonce is {} bytes, expected {} bytes'.format(len(n), crypto_box_NONCEBYTES))

    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise Exception('Public key is {} bytes, expected {} bytes'.format(len(pk), crypto_box_PUBLICKEYBYTES))

    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise Exception('Secret key is {} bytes, expected {} bytes'.format(len(sk), crypto_box_SECRETKEYBYTES))

    if len(c) < crypto_box_MACBYTES:
        raise Exception('Ciphertext is {} bytes, expected at least {} bytes'.format(len(c), crypto_box_MACBYTES))

    buf = ffi.new('unsigned char[]', len(c) - crypto_box_MACBYTES)
    ret = lib.crypto_box_open_easy(buf, c, len(c), n, pk, sk)
    if ret != 0:
        raise Exception('Failed to verify ciphertext')

    return bytes(buf)

def crypto_sign_keypair():
    pk = ffi.new('unsigned char[]', crypto_sign_PUBLICKEYBYTES)
    sk = ffi.new('unsigned char[]', crypto_sign_SECRETKEYBYTES)
    lib.crypto_sign_keypair(pk, sk) 
    return (bytes(pk), bytes(sk))


def crypto_sign(m, sk):
    if len(sk) != crypto_sign_SECRETKEYBYTES:
        raise Exception('Secret key is {} bytes, expected {} bytes'.format(len(sk), crypto_sign_SECRETKEYBYTES))

    buf = ffi.new('unsigned char[]', crypto_sign_BYTES + len(m))
    smlen = ffi.new('unsigned long long *')
    lib.crypto_sign(buf, smlen, m, len(m), sk)
    return bytes(buf[0:smlen[0]])

def crypto_sign_open(sm, pk):
  if len(pk) != crypto_sign_PUBLICKEYBYTES:
       raise Exception('Public key is {} bytes, expected {} bytes'.format(len(pk), crypto_sign_PUBLICKEYBYTES))

  buf = ffi.new('unsigned char[]', len(sm))
  mlen = ffi.new('unsigned long long *')
  ret = lib.crypto_sign_open(buf, mlen, sm, len(sm), pk)
  if ret != 0:
      raise Exception('Failed to verify message with public key')

  return bytes(buf[0:mlen[0]])


if __name__ == '__main__':
    nonce = random_bytes(24)
    key = random_bytes(32)
    ct = crypto_secretbox_easy(b'secret box test', nonce, key)
    print(ct)
    pt = crypto_secretbox_open_easy(ct, nonce, key)
    print(pt)
    
    apk, ask = crypto_box_keypair()
    bpk, bsk = crypto_box_keypair()
    ct = crypto_box_easy(b'box test', nonce, bpk, ask)
    print(ct)
    pt = crypto_box_open_easy(ct, nonce, apk, bsk)
    print(pt)

    pk, sk = crypto_sign_keypair()
    sm = crypto_sign(b'sign test', sk)
    print(sm)
    m = crypto_sign_open(sm, pk)
    print(m)
