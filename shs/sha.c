#include <stdio.h>
#include <string.h>
#include <time.h>

#include "rand.h"
#include "fips.h"

#include <openssl/evp.h>
#include <openssl/err.h>

const size_t DIGEST_LENGTH = 40;

void print_hex(FILE *out, const char *s) {
  while(*s)
    fprintf(out, "%02x", (unsigned char) *s++);
    fprintf(out, "\n");
}

unsigned int calc_hash(EVP_MD *md, const char* in, size_t size, unsigned char* out) {
    unsigned int md_len = -1;
    if (NULL != md) {
        EVP_MD_CTX mdctx;
        FIPS_md_ctx_init(&mdctx);
        FIPS_digestinit(&mdctx, md);
        FIPS_digestupdate(&mdctx, in, size);
        FIPS_digestfinal(&mdctx, out, &md_len);
        FIPS_md_ctx_cleanup(&mdctx);
    }
    return md_len;
}
typedef enum { false, true } bool;

int main(int argc, char *argv[]) {
    if (FIPS_init(1) != 1) {
        unsigned long err_code = ERR_get_error();

        const size_t ERR_BUFFER_SIZE = 120;
        char *err_buf = (char*)malloc(sizeof(char) * ERR_BUFFER_SIZE);
        ERR_error_string(err_code, err_buf);

        printf("error while initializing FIPS mode: %s", err_buf);
        return 1;
    }

    EVP_MD *md = NULL;
    bool use_rand = false;
    int i = 0;

    for (i; i < argc; i++) {
        if (strcmp(argv[i], "-sha1") == 0) {
            md = FIPS_evp_sha1();
            continue;
        }
        if (strcmp(argv[i], "-sha224") == 0) {
            md = FIPS_evp_sha224();
            continue;
        }
        if (strcmp(argv[i], "-sha256") == 0) {
            md = FIPS_evp_sha256();
            continue;
        }
        if (strcmp(argv[i], "-sha384") == 0) {
            md = FIPS_evp_sha384();
            continue;
        }
        if (strcmp(argv[i], "-sha512") == 0) {
            md = FIPS_evp_sha512();
            continue;
        }

        if (strcmp(argv[i], "-use-rand") == 0) {
            use_rand = true;
            continue;
        }
    }

    char *in;
    if (use_rand == true) {
        const size_t BUFFER_SIZE = 40;
        srand(time(NULL) * BUFFER_SIZE);
        char* buffer = (char*) malloc(sizeof(char) * BUFFER_SIZE);
        rand_str(buffer, BUFFER_SIZE);

        in = buffer;
    } else {
        in = (char *)argv[argc-1];
    }

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_ciphers();

    unsigned char* hash = (unsigned char*) malloc(sizeof(unsigned char) * DIGEST_LENGTH);
    calc_hash(md, in, strlen(in), hash);
    print_hex(stdout, hash);
}
