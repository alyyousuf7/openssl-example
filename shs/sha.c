#include <stdio.h>
#include <string.h>
#include <time.h>

#include "rand.h"
#include "fips.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#define SHA512_224_DIGEST_LENGTH 28
#define SHA512_256_DIGEST_LENGTH 32

const size_t DIGEST_LENGTH = 40;

static const EVP_MD sha512_224_md;
static const EVP_MD sha512_256_md;

static int init512_224(EVP_MD_CTX *ctx);
static int init512_256(EVP_MD_CTX *ctx);
static int update512(EVP_MD_CTX *ctx, const void *data, size_t count);
static int final512(EVP_MD_CTX *ctx, unsigned char *md);

const EVP_MD *FIPS_evp_sha512_224(void);
const EVP_MD *FIPS_evp_sha512_256(void);

void print_hex(FILE *out, const char *s, int size)
{
    int i;
    for (i = 0; i < size; i++)
        fprintf(out, "%02x", (unsigned char)*s++);
    fprintf(out, "\n");
}

unsigned int calc_hash(EVP_MD *md, const char *in, size_t size, unsigned char *out)
{
    unsigned int md_len = -1;
    if (NULL != md)
    {
        EVP_MD_CTX mdctx;
        EVP_MD_CTX_init(&mdctx);
        EVP_DigestInit_ex(&mdctx, md, NULL);
        EVP_DigestUpdate(&mdctx, in, size);
        EVP_DigestFinal_ex(&mdctx, out, &md_len);
        EVP_MD_CTX_cleanup(&mdctx);
    }
    return md_len;
}
typedef enum { false, true } bool;

int main(int argc, char *argv[])
{
    if (FIPS_init(1) != 1)
    {
        unsigned long err_code = ERR_get_error();

        const size_t ERR_BUFFER_SIZE = 120;
        char *err_buf = (char *)malloc(sizeof(char) * ERR_BUFFER_SIZE);
        ERR_error_string(err_code, err_buf);

        printf("error while initializing FIPS mode: %s", err_buf);
        return 1;
    }

    EVP_MD *md = NULL;
    bool use_rand = false;
    int i = 0;
    for (i; i < argc; i++)
    {
        if (strcmp(argv[i], "-sha1") == 0)
        {
            md = FIPS_evp_sha1();
            continue;
        }
        if (strcmp(argv[i], "-sha224") == 0)
        {
            md = FIPS_evp_sha224();
            continue;
        }
        if (strcmp(argv[i], "-sha256") == 0)
        {
            md = FIPS_evp_sha256();
            continue;
        }
        if (strcmp(argv[i], "-sha384") == 0)
        {
            md = FIPS_evp_sha384();
            continue;
        }
        if (strcmp(argv[i], "-sha512") == 0)
        {
            md = FIPS_evp_sha512();
            continue;
        }
        if (strcmp(argv[i], "-sha512-224") == 0)
        {
            md = FIPS_evp_sha512_224();
            continue;
        }
        if (strcmp(argv[i], "-sha512-256") == 0)
        {
            md = FIPS_evp_sha512_256();
            continue;
        }

        if (strcmp(argv[i], "-use-rand") == 0)
        {
            use_rand = true;
            continue;
        }
    }

    char *in;
    if (use_rand == true)
    {
        const size_t BUFFER_SIZE = 40;
        srand(time(NULL) * BUFFER_SIZE);
        char *buffer = (char *)malloc(sizeof(char) * BUFFER_SIZE);
        rand_str(buffer, BUFFER_SIZE);

        in = buffer;
    } else {
        in = (char *)argv[argc - 1];
    }

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_ciphers();

    unsigned char *hash = (unsigned char *)malloc(sizeof(unsigned char) * DIGEST_LENGTH);
    int len = calc_hash(md, in, strlen(in), hash);
    print_hex(stdout, hash, len);
}

static const EVP_MD sha512_224_md = {
    922,
    920,
    SHA512_224_DIGEST_LENGTH,
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT | EVP_MD_FLAG_FIPS,
    init512_224,
    update512,
    final512,
    NULL,
    NULL,
    EVP_PKEY_NULL_method,
    SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA512_CTX),
};

static const EVP_MD sha512_256_md = {
    923,
    921,
    SHA512_256_DIGEST_LENGTH,
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT | EVP_MD_FLAG_FIPS,
    init512_256,
    update512,
    final512,
    NULL,
    NULL,
    EVP_PKEY_NULL_method,
    SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA512_CTX),
};

int SHA512_224_Init(SHA512_CTX *c)
{
    c->h[0] = U64(0x8c3d37c819544da2);
    c->h[1] = U64(0x73e1996689dcd4d6);
    c->h[2] = U64(0x1dfab7ae32ff9c82);
    c->h[3] = U64(0x679dd514582f9fcf);
    c->h[4] = U64(0x0f6d2b697bd44da8);
    c->h[5] = U64(0x77e36f7304c48942);
    c->h[6] = U64(0x3f9d85a86a1d36c8);
    c->h[7] = U64(0x1112e6ad91d692a1);

    c->Nl = 0;
    c->Nh = 0;
    c->num = 0;
    c->md_len = SHA512_DIGEST_LENGTH;
    return 1;
}

int SHA512_256_Init(SHA512_CTX *c)
{
    c->h[0] = U64(0x22312194fc2bf72c);
    c->h[1] = U64(0x9f555fa3c84c64c2);
    c->h[2] = U64(0x2393b86b6f53b151);
    c->h[3] = U64(0x963877195940eabd);
    c->h[4] = U64(0x96283ee2a88effe3);
    c->h[5] = U64(0xbe5e1e2553863992);
    c->h[6] = U64(0x2b0199fc2c85b8aa);
    c->h[7] = U64(0x0eb72ddc81c52ca2);

    c->Nl = 0;
    c->Nh = 0;
    c->num = 0;
    c->md_len = SHA512_DIGEST_LENGTH;
    return 1;
}

static int init512_224(EVP_MD_CTX *ctx) { return SHA512_224_Init(ctx->md_data); }
static int init512_256(EVP_MD_CTX *ctx) { return SHA512_256_Init(ctx->md_data); }
static int update512(EVP_MD_CTX *ctx, const void *data, size_t count) { return SHA512_Update(ctx->md_data, data, count); }
static int final512(EVP_MD_CTX *ctx, unsigned char *md) { return SHA512_Final(md, ctx->md_data); }
const EVP_MD *FIPS_evp_sha512_224(void) { return (&sha512_224_md); }
const EVP_MD *FIPS_evp_sha512_256(void) { return (&sha512_256_md); }
