#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define KEY "PASSWORD"
#define IV "01234567890123412501234560123456"

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

#endif
