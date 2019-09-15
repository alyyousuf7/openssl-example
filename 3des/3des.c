#include <openssl/des.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    DES_cblock cb1 = {0xFA, 0x5E, 0xAE, 0xBC, 0x19, 0x12, 0x13, 0xA1};
    DES_cblock cb2 = {0xAF, 0xA4, 0xAE, 0xCB, 0xED, 0x45, 0x13, 0x1E};
    DES_cblock cb3 = {0xB3, 0x24, 0xAE, 0xDE, 0xAD, 0x98, 0x31, 0x4E};

    DES_key_schedule ks1, ks2, ks3;

    DES_cblock cblock = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    unsigned char *plainText = argv[1];
    int plainTextLen = strlen(plainText);
    printf("Plain Text : %s\n", plainText);

    char *cipher[plainTextLen];
    char *text[plainTextLen];
    memset(cipher, 0, plainTextLen);
    memset(text, 0, plainTextLen);

    DES_set_odd_parity(&cblock);
    DES_set_odd_parity(&cb1);
    DES_set_odd_parity(&cb2);
    DES_set_odd_parity(&cb3);

    if (DES_set_key_checked(&cb1, &ks1) ||
        DES_set_key_checked(&cb2, &ks2) ||
        DES_set_key_checked(&cb3, &ks3))
    {
        printf("Key error, exiting ....\n");
        return 1;
    }

    DES_ede3_cbc_encrypt((const unsigned char *)plainText,
                         (unsigned char *)cipher,
                         plainTextLen, &ks1, &ks2, &ks3,
                         &cblock, DES_ENCRYPT);
    printf("Encrypted : %32.32s\n", cipher);

    //-----------------------------------------------
    // You need to start with the same cblock value
    memset(cblock, 0, sizeof(DES_cblock));
    DES_set_odd_parity(&cblock);

    //-----------------------------------------------
    // I think you need to use 32 for the cipher len.
    // You can't use strlen(cipher) because if there
    // is a 0x00 in the middle of the cipher strlen
    // will stop there and the length would be short
    DES_ede3_cbc_encrypt((const unsigned char *)cipher,
                         (unsigned char *)text,
                         32, &ks1, &ks2, &ks3,
                         &cblock, DES_DECRYPT);
    printf("Decrypted : %s\n", text);
}