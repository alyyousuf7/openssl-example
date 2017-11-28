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

void main(int argc, char **argv) {
    initialize_fips(1);

    unsigned char *key = (unsigned char *)"example key 1234";
    unsigned char *iv = (unsigned char *)"0123456789012341";
    unsigned char *plaintext = (unsigned char *)"exampleplaintext";
    unsigned char *mode = (unsigned char *)"cbc";

    if (argc == 2) {
        mode = argv[1];
    }

    printf(mode);

    // Encryption
    fprintf(stdout, "\nEncryption:\n");
    unsigned char ciphertext[32];
    int ciphertext_len;
    ciphertext_len = encdec(plaintext, strlen((char *)plaintext), key, strlen((char *)key), iv, ciphertext, mode, 1);
    if (ciphertext_len == 0) {
        return;
    }

    fprintf(stdout, "Plaintext: %s\n", plaintext);
    fprintf(stdout, "IV: ");
    print_hex(stdout, iv);
    fprintf(stdout, "Ciphertext [%d]: ", ciphertext_len);
    print_hex(stdout, ciphertext);

    // Decryption
    fprintf(stdout, "\nDecryption:\n");
    unsigned char pt_tmp[32];
    int pt_len;
    pt_len = encdec(ciphertext, strlen((char *)ciphertext), key, strlen((char *)key), iv, pt_tmp, mode, 0);
    if (pt_len == 0) {
        return;
    }
    // Print decrypted
    fprintf(stdout, "Plaintext [%d]: %s\n", pt_len, pt_tmp);
}

void print_hex(FILE *out, const char *s)
{
  while(*s)
    fprintf(out, "%x", (unsigned char) *s++);
  fprintf(out, "\n");
}

int encdec(unsigned char *plaintext, int plaintext_len, unsigned char *key, int key_len, unsigned char *iv, unsigned char *ciphertext, unsigned char *mode, int enc) {
    // New CBC Encrypter
    EVP_CIPHER *evpCipher;
    switch (key_len) {
    case 16:
        if (strcmp(mode,"cbc")==0) {
            evpCipher = EVP_aes_128_cbc();
        }else{
            fprintf(stderr, "invalid mode\n");
            return 0;
        }
        break;
    case 24:
        if (strcmp(mode,"cbc")==0) {
            evpCipher = EVP_aes_192_cbc();
        }else{
            fprintf(stderr, "invalid mode\n");
            return 0;
        }
        break;
    case 32:
        if (strcmp(mode,"cbc")==0) {
            evpCipher = EVP_aes_256_cbc();
        }else{
            fprintf(stderr, "invalid mode\n");
            return 0;
        }
        break;
    default:
        fprintf(stderr, "invalid aes key len\n");
        return 0;
    }

    EVP_CIPHER_CTX *ctx = malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(ctx);
    if (EVP_CipherInit_ex(ctx, evpCipher, NULL, NULL, NULL, enc) <= 0) {
        fprintf(stderr, "EVP_CipherInit_ex failed (1)\n");
        return 0;
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc) <= 0) {
        fprintf(stderr, "EVP_CipherInit_ex failed (2)\n");
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Crypt Block
    if (plaintext_len % key_len != 0) {
        fprintf(stderr, "plaintext is not a multiple of blocksize\n");
        return 0;
    }

    // crypt
    int outLen;
    if (EVP_CipherUpdate(ctx,
        	&ciphertext[0], &outLen,
			&plaintext[0], plaintext_len) != 1) {
			return 0;
    }

    if (plaintext_len != outLen) {
        fprintf(stderr, "openssl did not encryt all of plaintext %d, %d\n", plaintext_len, outLen);
        return 0;
    }
}
