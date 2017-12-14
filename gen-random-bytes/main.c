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

void selftest(){
    if(FIPS_selftest()) {
        fprintf(stdout, "FUNCTION: %s, LOG: Selftest Passed.", __func__);
    }
    else {
        fprintf(stderr, "FUNCTION: %s, LOG: Selftest Failed.", __func__);
        ERR_load_crypto_strings();
        fprintf(stderr, ", ERROR: ");
        ERR_print_errors_fp(stderr);
    }
}

void generate_random(int nbytes){
    unsigned char *buff = malloc(sizeof(unsigned char)*nbytes);

    if(RAND_bytes(buff, nbytes)){

        fprintf(stdout, "FUNCTION: %s, LOG: RANDOM NUMBER GENERATION SUCCESSFUL\n", __func__);
    }
    else {
        fprintf(stdout, "FUNCTION: %s, LOG: RANDOM NUMBER GENERATION FAILURE\n", __func__);
    }

    BIGNUM *p = BN_bin2bn(buff, nbytes, NULL);

    char * number_str = BN_bn2dec(p);
    printf("%s\n", number_str);
}

int main() {
    //fips mode *ON*
    initialize_fips(1);

    //generate random number of given bytes
    generate_random(1);
    return 0;
}