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

//Show status
void fips_mode(){
    if(FIPS_mode()){
        fprintf(stdout, "FUNCTION: %s, LOG: FIPS MODE ENABLE\n", __func__);
    } else {
        fprintf(stdout, "FUNCTION: %s, LOG: FIPS MODE DISABLE\n", __func__);
    }
}


int main() {
    //fips mode *ON*
    initialize_fips(1);
    //check self test status
    fips_mode();

    //fips mode *OFF*
    initialize_fips(0);
    //check self test status
    fips_mode();

    return 0;
}
