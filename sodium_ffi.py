from cffi import FFI
ffi = FFI()

ffi.set_source("_sodium",
    """
#include <sodium.h>
    """,
    libraries=['sodium'])

ffi.cdef("""
void randombytes_buf(void * const buf, const size_t size);

size_t crypto_secretbox_keybytes();
size_t crypto_secretbox_noncebytes();
size_t crypto_secretbox_macbytes();
int crypto_secretbox_easy(unsigned char *c, const unsigned char *m,
    unsigned long long mlen, const unsigned char *n,
    const unsigned char *k);
int crypto_secretbox_open_easy(unsigned char *m, const unsigned char *c,
   unsigned long long clen, const unsigned char *n,
   const unsigned char *k);

size_t crypto_box_publickeybytes();
size_t crypto_box_secretkeybytes();
size_t crypto_box_noncebytes();
size_t crypto_box_macbytes();
int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
int crypto_box_easy(unsigned char *c, const unsigned char *m,
    unsigned long long mlen, const unsigned char *n,
    const unsigned char *pk, const unsigned char *sk);
int crypto_box_open_easy(unsigned char *m, const unsigned char *c,
    unsigned long long clen, const unsigned char *n,
    const unsigned char *pk, const unsigned char *sk);

size_t crypto_sign_publickeybytes();
size_t crypto_sign_secretkeybytes();
size_t crypto_sign_bytes();
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
    const unsigned char *sm, unsigned long long smlen,
    const unsigned char *pk);

size_t crypto_pwhash_scryptsalsa208sha256_saltbytes();
int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
   unsigned long long outlen,
   const char * const passwd,
   unsigned long long passwdlen,
   const unsigned char * const salt,
   unsigned long long opslimit,
   size_t memlimit);

""")

if __name__ == "__main__":
    ffi.compile()
