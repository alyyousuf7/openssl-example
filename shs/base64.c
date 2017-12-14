#include <openssl/evp.h>
#include <openssl/buffer.h>

// TODO: Move to helpers/commons
int b64_enc(const unsigned char *buffer, size_t size, char **out) {
    BIO *bio, *b64;
    BUF_MEM *buf_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, size);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buf_ptr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *out = (*buf_ptr).data;

    return 0;
}