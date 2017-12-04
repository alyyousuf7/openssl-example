#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

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

int main(int argc, char *argv[])
{
    initialize_fips(1);

    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char *password = NULL;
    const unsigned char *salt = NULL;
    int i;
    unsigned char *cipher_name = "aes-256-cbc";
    unsigned char *digest_name = "sha1";
    int password_len = 0;

    if (!(argc == 4 || argc == 5)) {
        fprintf(stderr, "USAGE: %s [cipher] [digest] [password]\n", argv[0]);
        return 1;
    }else{
        cipher_name = argv[1];
        digest_name = argv[2];
        password = argv[3];
        password_len = strlen(password);
        if (argc == 5) {
            password_len = atoi(argv[4]);
        }
    }

    OpenSSL_add_all_algorithms();

    fprintf(stdout, "Password: ");
    if(strcmp(password, "-rand") == 0) {
        if (password_len == 0) {
            fprintf(stderr, "Rand password cannot be zero length\n");
            return 1;
        }
        RAND_bytes(password, password_len);
        fprintf(stdout, "Using DRBG for generating bytes [%d]: ", password_len);
    }
    for(i=0; i<password_len; ++i) { printf("%02x", password[i]); } printf("\n");

    cipher = EVP_get_cipherbyname(cipher_name);
    if(!cipher) { fprintf(stderr, "no such cipher\n"); return 1; }

    dgst=EVP_get_digestbyname(digest_name);
    if(!dgst) { fprintf(stderr, "no such digest\n"); return 1; }

    if(!EVP_BytesToKey(cipher, dgst, salt,
        (unsigned char *) password,
        strlen(password), 1, key, iv))
    {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

    printf("Key: "); for(i=0; i<cipher->key_len; ++i) { printf("%02x", key[i]); } printf("\n");
    printf("IV: "); for(i=0; i<cipher->iv_len; ++i) { printf("%02x", iv[i]); } printf("\n");

    return 0;
}
