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
    EVP_PKEY          *pkey     = NULL;
    int               eccgrp;
    char*             md_type   = "nohash";
    char*             keypath   = "ecdsa-private.pem";
    char*             datapath  = "data.bin";
    char*             signaturepath = "signature.bin";

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
    
    if (PEM_read_bio_PrivateKey(keybio, &pkey, NULL, NULL) == NULL) {
        BIO_printf(outbio, "PEM_read_bio_PrivateKey error.\n");
        goto FreeAll;
    }
    BIO_free_all(keybio);

    /* -------------------------------------------------------- *
    * Now we show how to extract EC-specifics from the key     *
    * ---------------------------------------------------------*/
    myecc = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);

    /* ---------------------------------------------------------- *
    * Here we print the key length, and extract the curve type.  *
    * ---------------------------------------------------------- */
    BIO_printf(outbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
    BIO_printf(outbio, "ECC Key type: %s\n\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));

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
    int hashlen;
    if (strcmp(md_type, "nohash") == 0) {
        hash = data;
        hashlen = datalen;
    } else if (digest_message(md_type, data, datalen, &hash, &hashlen) != 1) {
        BIO_printf(outbio, "Hash error.\n");
        goto FreeAll;
    }

    /* ---------------------------------------------------------- *
    * Generate Signature                                         *
    * ---------------------------------------------------------- */
    ECDSA_SIG *signature = ECDSA_do_sign(hash, hashlen, myecc);
    if (NULL == signature) {
        BIO_printf(outbio, "ECDSA_do_sign error.\n");
        goto FreeAll;
    }

    /* ---------------------------------------------------------- *
    * Write DER to a file                                        *
    * ---------------------------------------------------------- */
    int sigSize = i2d_ECDSA_SIG(signature, NULL);
    unsigned char* derSig = malloc(sigSize);
    unsigned char* p = derSig; // Some black magic happening here
    sigSize = i2d_ECDSA_SIG(signature, &p);

    sigbio = BIO_new(BIO_s_file());
    if (BIO_write_filename(sigbio, signaturepath) != 1) {
        BIO_printf(outbio, "Signature BIO_write_filename error.\n");
        goto FreeAll;
    }
    if (BIO_write(sigbio, derSig, sigSize) < sigSize) {
        BIO_printf(outbio, "Signature BIO_write error.\n");
        goto FreeAll;
    }
    BIO_printf(outbio, "Signature written to %s\n", signaturepath);

    /* ---------------------------------------------------------- *
    * Free up all structures                                     *
    * ---------------------------------------------------------- */
FreeAll:
    ERR_print_errors(outbio);
    ECDSA_SIG_free(signature);
    BIO_free_all(sigbio);
    BIO_free_all(databio);
    BIO_free_all(outbio);
    EVP_PKEY_free(pkey);
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