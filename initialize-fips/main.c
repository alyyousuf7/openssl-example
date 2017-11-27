#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

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

int main() {
    //fips mode *ON*
    initialize_fips(1);
    return 0;
}
