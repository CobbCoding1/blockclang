#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/sha.h>

unsigned char *create_sha256(const unsigned char str[], unsigned char *buffer);

#endif
