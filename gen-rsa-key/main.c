#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void initialize_fips(int mode) {
    if(FIPS_mode_set(mode)) {
        fprintf(stdout, "FIPS Mode Set\n\n");
    }
    else {
        fprintf(stderr, "FIPS Mode Set Error:\n");
        ERR_print_errors_fp(stderr);
    }
}

int main(int argc, char* argv[]) {
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    initialize_fips(1);

    BIO               *outbio = NULL;
    BIO               *keybio = NULL;
    BIGNUM            *bne    = NULL;
    RSA               *rsa    = NULL;
    EVP_PKEY          *pkey   = NULL;
    int               kBits   = 1024;

    /* ---------------------------------------------------------- *
    * Create the Input/Output BIO's.                             *
    * ---------------------------------------------------------- */
    outbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* ---------------------------------------------------------- *
    * Read arguments.                                            *
    * ---------------------------------------------------------- */
    if (!(argc >= 2)) {
        BIO_printf(outbio, "USAGE: %s [bits]\n\n", argv[0]);
    } else {
        kBits = atoi(argv[1]);
    }

    /* ---------------------------------------------------------- *
    * Generate Key.                                              *
    * ---------------------------------------------------------- */
    bne = BN_new();
    if (BN_set_word(bne, 65537) != 1) {
        BIO_printf(outbio, "BN_set_word error.\n");
        goto FreeAll;
    }

    rsa = RSA_new();
    if (FIPS_rsa_x931_generate_key_ex(rsa, kBits, bne, NULL) != 1) {
        BIO_printf(outbio, "RSA_generate_key_ex error.\n");
        goto FreeAll;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        BIO_printf(outbio, "EVP_PKEY_new error.\n");
        goto FreeAll;
    }

    if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        BIO_printf(outbio, "EVP_PKEY_set1_RSA error.\n");
        goto FreeAll;
    }

    /* ---------------------------------------------------------- *
    * Print Private/Public Key.                                  *
    * ---------------------------------------------------------- */
    PEM_write_bio_RSAPrivateKey(outbio, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_PUBKEY(outbio, pkey);

FreeAll:
    ERR_print_errors(outbio);
    BN_free(bne);
    BIO_free_all(outbio);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
}