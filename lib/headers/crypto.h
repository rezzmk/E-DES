#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stdint.h>
#include <stdio.h>

/*
Algorithm enum, containing the different types of implementations present.
In this case, we support E-DES (Enhanced DES) and DES (in ECB mode)
Note: For DES, we're using Openssl
*/
typedef enum {EDES, DES} Algorithm;

/*
Encryption result structure as a generic way to return everything needed by the consumer of this library
*/
typedef struct {
    uint8_t *result;
    size_t length; 
} ENCRYPTION_RESULT;

/*
Encrypts payload
*/
extern ENCRYPTION_RESULT *encrypt(uint8_t *in, size_t in_sz);
/*
Decrypts payload
*/
extern ENCRYPTION_RESULT *decrypt(uint8_t *in, size_t in_sz);
/*
Initializes a new Encryption context
*/
extern void CAENC_CTX_new(Algorithm algo, uint8_t *key);
/*
Cleanup context
*/
extern void CAENC_CTX_cleanup();

#endif