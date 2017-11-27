#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

//Initialize
void initialize_fips(int mode){
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

// Zeroize
static int Zeroize()
{
    RSA *key;
    BIGNUM *bn;
    unsigned char userkey[16] =
            { 0x48, 0x50, 0xf0, 0xa3, 0x3a, 0xed, 0xd3, 0xaf, 0x6e, 0x47, 0x7f, 0x83, 0x02, 0xb1, 0x09, 0x68 };
    size_t i;
    int n;

    // return RSA structure
    key = FIPS_rsa_new();

    //BIGNUM
    bn = BN_new();
    if (!key || !bn)
        return 0;
    //SET BN to 65537
    BN_set_word(bn, 65537);

    //Generate key for RSA 1024 bit = 128Byte
    if (!RSA_generate_key_ex(key, 1024,bn,NULL))
        return 0;
    
    BN_free(bn);

    n = BN_num_bytes(key->d);

    printf(" Generated %d byte RSA private key\n", n);
    printf("\tBN key before Zeroize :\n");
    do_bn_print(stdout, key->d);

    FIPS_rsa_free(key);

    printf("\n Generated %d byte RSA private key\n", n);
    printf("\tBN key after Zeroize :\n");
    do_bn_print(stdout, key->d);
    printf("\n");

    return 1;
}


//Show Zeroize test status
void fips_zeroize(){
    if(Zeroize()){
        fprintf(stdout, "FUNCTION: %s, LOG: FIPS ZERORIZE SUCCESSFUL\n", __func__);
    } else {
        fprintf(stdout, "FUNCTION: %s, LOG: FIPS ZERORIZE FAILURE\n", __func__);
    }
}

int do_bn_print(FILE *out, const BIGNUM *bn)
{
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

int main() {
    //fips mode *ON*
    initialize_fips(1);    
    //Zeroize test
    fips_zeroize();

    return 0;
}
