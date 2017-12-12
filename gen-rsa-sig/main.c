#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define MAXBUFLEN 1000000

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

    BIO               *outbio   = NULL;
    BIO               *keybio   = NULL;
    BIO               *databio  = NULL;
    BIO               *sigbio   = NULL;
    RSA               *myrsa    = NULL;
    EVP_PKEY          *pkey     = NULL;
    EVP_PKEY_CTX      *ctx      = NULL;
    EVP_MD            *md       = EVP_sha();
    char*             md_type       = "sha";
    char*             padding_type  = "pkcs1v15";
    char*             keypath       = "rsa-private.pem";
    char*             datapath      = "data.bin";
    char*             signaturepath = "signature.bin";

    /* ---------------------------------------------------------- *
    * Create the Input/Output BIO's.                             *
    * ---------------------------------------------------------- */
    outbio  = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* ---------------------------------------------------------- *
    * Read arguments.                                            *
    * ---------------------------------------------------------- */
    if (!(argc >= 6)) {
        BIO_printf(outbio, "USAGE: %s [md] [padding] [keypath] [datapath] [signaturepath]\n\n", argv[0]);
    } else {
        md_type       = argv[1];
        padding_type  = argv[2];
        keypath       = argv[3];
        datapath      = argv[4];
        signaturepath = argv[5];
    }
    if (strcmp(md_type, "sha") == 0) {
        md = EVP_sha();
    } else if (strcmp(md_type, "sha1") == 0) {
        md = FIPS_evp_sha1();
    } else if (strcmp(md_type, "sha224") == 0) {
        md = FIPS_evp_sha224();
    } else if (strcmp(md_type, "sha256") == 0) {
        md = FIPS_evp_sha256();
    } else if (strcmp(md_type, "sha384") == 0) {
        md = FIPS_evp_sha384();
    } else if (strcmp(md_type, "sha512") == 0) {
        md = FIPS_evp_sha512();
    }

    /* ---------------------------------------------------------- *
    * Create the Input/Output BIO's for reading file.            *
    * ---------------------------------------------------------- */
    keybio = BIO_new(BIO_s_file());
    if (BIO_read_filename(keybio, keypath) != 1) {
        BIO_printf(outbio, "Key BIO_read_filename error.\n");
        goto FreeAll;
    }

    if (PEM_read_bio_RSAPrivateKey(keybio, &myrsa, NULL, NULL) == NULL) {
        BIO_printf(outbio, "PEM_read_bio_RSAPrivateKey error.\n");
        goto FreeAll;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        BIO_printf(outbio, "EVP_PKEY_new error.\n");
        goto FreeAll;
    }

    if (EVP_PKEY_set1_RSA(pkey, myrsa) != 1) {
        BIO_printf(outbio, "EVP_PKEY_set1_RSA error.\n");
        goto FreeAll;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        BIO_printf(outbio, "EVP_PKEY_CTX_new error.\n");
        goto FreeAll;
    }

    if (EVP_PKEY_sign_init(ctx) != 1) {
        BIO_printf(outbio, "EVP_PKEY_sign_init error.\n");
        goto FreeAll;
    }

    if (strcmp(padding_type, "pkcs1v15") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) {
            BIO_printf(outbio, "EVP_PKEY_CTX_set_rsa_padding error.\n");
            goto FreeAll;
        }
    } else if (strcmp(padding_type, "pss-auto") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) != 1) {
            BIO_printf(outbio, "EVP_PKEY_CTX_set_rsa_padding error.\n");
            goto FreeAll;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -2) != 1) {
            BIO_printf(outbio, "EVP_PKEY_CTX_set_rsa_pss_saltlen error.\n");
            goto FreeAll;
        }
    } else if (strcmp(padding_type, "pss-equal") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) != 1) {
            BIO_printf(outbio, "EVP_PKEY_CTX_set_rsa_padding error.\n");
            goto FreeAll;
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -1) != 1) {
            BIO_printf(outbio, "EVP_PKEY_CTX_set_rsa_pss_saltlen error.\n");
            goto FreeAll;
        }
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md) != 1) {
        BIO_printf(outbio, "EVP_PKEY_CTX_set_signature_md error.\n");
        goto FreeAll;
    }
    
    /* ---------------------------------------------------------- *
    * Read Data                                                  *
    * ---------------------------------------------------------- */
    BIO_printf(outbio, "Loading message from %s\n", datapath);

    databio = BIO_new(BIO_s_file());
    if (BIO_read_filename(databio, datapath) != 1) {
        BIO_printf(outbio, "Data BIO_read_filename error.\n");
        goto FreeAll;
    }
    char data[MAXBUFLEN + 1];
    int datalen = BIO_read(databio, data, MAXBUFLEN);
    if (datalen == 0) {
        BIO_printf(outbio, "Data BIO_read error.\n");
        goto FreeAll;
    }
    
    /* ---------------------------------------------------------- *
    * Create digest from data                                    *
    * ---------------------------------------------------------- */
    unsigned char *hash;
    size_t hlen = 0;
    size_t hashlen = 0;
    if (strcmp(md_type, "nohash") == 0) {
        hash = data;
        hlen = datalen;
    } else if (digest_message(md_type, data, datalen, &hash, &hlen) != 1) {
        BIO_printf(outbio, "Hash error.\n");
        goto FreeAll;
    }
    hashlen = hlen; // For some reasons, hlen changes

    /* ---------------------------------------------------------- *
    * Generate Signature                                         *
    * ---------------------------------------------------------- */
    size_t signature_len;
    if (EVP_PKEY_sign(ctx, NULL, &signature_len, hash, hashlen) != 1) {
        BIO_printf(outbio, "EVP_PKEY_sign error.\n");
        goto FreeAll;
    }
    
    unsigned char *signature = malloc(sizeof(unsigned char) * signature_len);
    if (EVP_PKEY_sign(ctx, signature, &signature_len, hash, hashlen) != 1) {
        BIO_printf(outbio, "EVP_PKEY_sign - 2 error.\n");
        goto FreeAll;
    }

    /* ---------------------------------------------------------- *
    * Write Signature to a file                                  *
    * ---------------------------------------------------------- */
    sigbio = BIO_new(BIO_s_file());
    if (BIO_write_filename(sigbio, signaturepath) != 1) {
        BIO_printf(outbio, "Signature BIO_write_filename error.\n");
        goto FreeAll;
    }
    if (BIO_write(sigbio, signature, signature_len) < signature_len) {
        BIO_printf(outbio, "Signature BIO_write error.\n");
        goto FreeAll;
    }
    BIO_printf(outbio, "Signature written to %s\n", signaturepath);

    /* ---------------------------------------------------------- *
    * Free up all structures                                     *
    * ---------------------------------------------------------- */
FreeAll:
    ERR_print_errors(outbio);
    BIO_free_all(sigbio);
    BIO_free_all(databio);
    BIO_free_all(outbio);
    RSA_free(myrsa);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return 0;
}

int digest_message(const unsigned char *type, const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
    int rv = 0;
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_create()) == NULL) {
        fprintf(stderr, "EVP_MD_CTX_create error.");
        goto FreeMdCtx;
    }

    EVP_MD *md = NULL;
    if (strcmp(type, "sha") == 0) {
        md = EVP_sha();
    } else if (strcmp(type, "sha1") == 0) {
        md = FIPS_evp_sha1();
    } else if (strcmp(type, "sha224") == 0) {
        md = FIPS_evp_sha224();
    } else if (strcmp(type, "sha256") == 0) {
        md = FIPS_evp_sha256();
    } else if (strcmp(type, "sha512") == 0) {
        md = FIPS_evp_sha512();
    } else if (strcmp(type, "md5") == 0) {
        md = EVP_md5();
    }

	if(1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "EVP_DigestInit_ex error.");
        goto FreeMdCtx;
    }

	if(1 != EVP_DigestUpdate(mdctx, message, message_len)) {
        fprintf(stderr, "EVP_DigestUpdate error.");
        goto FreeMdCtx;
    }

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(md))) == NULL) {
        fprintf(stderr, "OPENSSL_malloc error.");
        goto FreeMdCtx;
    }

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len)) {
        fprintf(stderr, "EVP_DigestFinal_ex error.");
        goto FreeMdCtx;
    }

    rv = 1;
FreeMdCtx:
	EVP_MD_CTX_destroy(mdctx);
    return rv;
}