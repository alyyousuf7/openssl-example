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
    EC_KEY            *myecc    = NULL;
    int               eccgrp;
    char*             md_type   = "nohash";
    char*             keypath   = "ecdsa-public.pem";
    char*             datapath  = "data.bin";
    char*             signaturepath = "signature.bin";

    /* ---------------------------------------------------------- *
    * These function calls initialize openssl for correct work.  *
    * ---------------------------------------------------------- */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* ---------------------------------------------------------- *
    * Create the Input/Output BIO's.                             *
    * ---------------------------------------------------------- */
    outbio  = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* ---------------------------------------------------------- *
    * Read arguments.                                            *
    * ---------------------------------------------------------- */
    if (!(argc >= 5)) {
        BIO_printf(outbio, "USAGE: %s [md] [keypath] [datapath] [signaturepath]\n\n", argv[0]);
    } else {
        md_type  = argv[1];
        keypath  = argv[2];
        datapath = argv[3];
        signaturepath = argv[4];
    }

    /* ---------------------------------------------------------- *
    * Create the Input/Output BIO's for reading file.            *
    * ---------------------------------------------------------- */
    keybio = BIO_new(BIO_s_file());
    if (BIO_read_filename(keybio, keypath) != 1) {
        BIO_printf(outbio, "Key BIO_read_filename error.\n");
        goto FreeAll;
    }
    
    if (PEM_read_bio_EC_PUBKEY(keybio, &myecc, NULL, NULL) == NULL) {
        BIO_printf(outbio, "d2i_EC_PUBKEY_bio error.\n");
        goto FreeAll;
    }
    BIO_free_all(keybio);
    const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);

    /* ---------------------------------------------------------- *
    * Here we extract the curve type.                            *
    * ---------------------------------------------------------- */
    BIO_printf(outbio, "ECC Key type: %s\n\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));

    /* ---------------------------------------------------------- *
    * Read Data from file                                        *
    * ---------------------------------------------------------- */
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
    int hashlen;
    if (strcmp(md_type, "nohash") == 0) {
        hash = data;
        hashlen = datalen;
    } else if (digest_message(md_type, data, datalen, &hash, &hashlen) != 1) {
        BIO_printf(outbio, "Hash error.\n");
        goto FreeAll;
    }

    /* ---------------------------------------------------------- *
    * Read Signature DER from file                               *
    * ---------------------------------------------------------- */
    sigbio = BIO_new(BIO_s_file());
    if (BIO_read_filename(sigbio, signaturepath) != 1) {
        BIO_printf(outbio, "Signature BIO_read_filename error [%s].\n", signaturepath);
        goto FreeAll;
    }
    char derSig[MAXBUFLEN + 1];
    int sigSize = BIO_read(sigbio, derSig, MAXBUFLEN);
    if (sigSize == 0) {
        BIO_printf(outbio, "Signature BIO_read error.\n");
        goto FreeAll;
    }

    /* ---------------------------------------------------------- *
    * Verify Signature                                           *
    * ---------------------------------------------------------- */
    unsigned char *p = derSig;
    ECDSA_SIG *signature = d2i_ECDSA_SIG(NULL, &p, sigSize);
    if (signature == NULL) {
        BIO_printf(outbio, "Failed to parse Signature DER.\n");
        goto FreeAll;
    }

    if (!ECDSA_do_verify(hash, hashlen, signature, myecc)) {
        BIO_printf(outbio, "Verification failed.\n");
        goto FreeAll;
    } else {
        BIO_printf(outbio, "Verification success!\n");
    }

    /* ---------------------------------------------------------- *
    * Free up all structures                                     *
    * ---------------------------------------------------------- */
FreeAll:
    ERR_print_errors(outbio);
    ECDSA_SIG_free(signature);
    BIO_free_all(sigbio);
    BIO_free_all(databio);
    BIO_free_all(outbio);
    EC_KEY_free(myecc);

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