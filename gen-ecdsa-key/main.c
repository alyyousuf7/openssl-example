#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void initialize_fips(int mode) {
    if(FIPS_mode_set(mode)) {
        fprintf(stdout, "FUNCTION: %s, LOG: FIPS MODE SET TO %d\n", __func__, mode);
    }
    else {
        fprintf(stderr, "FUNCTION: %s, LOG: FIPS MODE NOT SET %d", __func__, mode);
        ERR_load_crypto_strings();
        fprintf(stderr, ", ERROR: ");
        ERR_print_errors_fp(stderr);
    }
}

int main() {
    initialize_fips(1);

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (EC_KEY_generate_key(key) != 1) {
        fprintf(stderr, "Failed to generate key");
        return;
    }

    // Public Key
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (EC_POINT_get_affine_coordinates_GFp(
        EC_KEY_get0_group(key),
        EC_KEY_get0_public_key(key),
        x, y, ctx
    ) != 1) {
        fprintf(stderr, "Public key error");
        return;
    }
    BN_CTX_free(ctx);
    
    // Private key
    BIGNUM *d = EC_KEY_get0_private_key(key);

    // Print key
    fprintf(stdout, "X: ");
    do_bn_print(stdout, x);
    fprintf(stdout, "\nY: ");
    do_bn_print(stdout, y);
    fprintf(stdout, "\nD: ");
    do_bn_print(stdout, d);
    fprintf(stdout, "\n");

    // Some data for signing
    unsigned char hash[] = "DnA68SOtgjCZRYq5NdjXf3RRPXKHHD44T3nDCilsC3CIQipZ1BblvKkLFyWofelxY36N8LDmewuqzg5fRdk6f4Khrbl3K5Mpgtqk";
    
    fprintf(stdout, "\nGenerating Signature\n");
    fprintf(stdout, "\nHASH: %s", hash);
  
    ECDSA_SIG * signature = ECDSA_do_sign(hash, strlen(hash), key);
  
    if (signature == NULL) {
        printf("Failed to generate EC Signature\n");
        return NULL;
    }   

    if (verifySignature(hash, key, signature) != 1) {
        return 0;
    }
    

    BN_free(x);
    BN_free(y);
    EC_KEY_free(key);

    return 1;
}

int do_bn_print(FILE *out, const BIGNUM *bn) {
    int len, i;
    unsigned char *tmp;
    len = BN_num_bytes(bn);
    if (len == 0)
    {
        fputs("00", out);
        return 1;
    }

    tmp = OPENSSL_malloc(len);
    if (!tmp)
    {
        fprintf(stderr, "Memory allocation error\n");
        return 0;
    }
    BN_bn2bin(bn, tmp);
    for (i = 0; i < len; i++)
        fprintf(out, "%02x", tmp[i]);
    OPENSSL_free(tmp);
    return 1;
}

int verifySignature(unsigned char * hash, EC_KEY * eckey, ECDSA_SIG * signature) {
    int verifyStatus = ECDSA_do_verify(hash, strlen(hash), signature, eckey);
    
    if (verifyStatus != 1) {
      printf("\nFailed to verify EC Signature\n");
      return 0;
    }
    
    printf("\nVerifed EC Signature\n");
    return verifyStatus;
}