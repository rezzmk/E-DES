#include "caencryption.h"
#include "edes.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>

bool g_initialized = false;
Algorithm g_current_ctx_algo = EDES;
EVP_CIPHER_CTX *des_ctx;
uint8_t *g_key;

ENCRYPTION_RESULT *encrypt(uint8_t *in, size_t in_sz) {
    if (!g_initialized) {
        return NULL;
    }

    ENCRYPTION_RESULT *result = malloc(sizeof(ENCRYPTION_RESULT));
    if (g_current_ctx_algo == EDES) {
        EDES_Result *edes_result = malloc(sizeof(EDES_Result));
        edes_result = edes_encrypt(in, in_sz, g_key);

        result->length = edes_result->encrypted_len;
        result->result = edes_result->encrypted;
    }
    else if (g_current_ctx_algo == DES) {
        int32_t ret;
        ret = EVP_EncryptInit_ex(des_ctx, EVP_des_ecb(), NULL, g_key, NULL);
        assert(ret == 1);

        ret = EVP_CIPHER_CTX_set_padding(des_ctx, 0);
        assert(ret == 1);

        int outl;
        uint8_t *output = malloc((in_sz) * sizeof(uint8_t));
        ret = EVP_EncryptUpdate(des_ctx, output, &outl, in, in_sz);
        assert(ret == 1);
        assert(outl == in_sz);

        int tmp = outl;

        ret = EVP_EncryptFinal_ex(des_ctx, &output[outl], &outl);
        assert(ret == 1);
        assert(outl == 0);
        outl += tmp;

        result->length = outl;
        result->result = output;
    }

    return result;
}

ENCRYPTION_RESULT *decrypt(uint8_t *in, size_t in_sz) {
    if (!g_initialized) {
        return NULL;
    }

    ENCRYPTION_RESULT *result = malloc(sizeof(ENCRYPTION_RESULT));
    if (g_current_ctx_algo == EDES) {
        EDES_Decryption *edes_result = malloc(sizeof(EDES_Result));
        edes_result = edes_decrypt(in, in_sz, g_key);

        result->length = edes_result->message_len;
        result->result = edes_result->message;
    }
    else if (g_current_ctx_algo == DES) {
        int tmp;

        int ret = EVP_DecryptInit_ex(des_ctx, EVP_des_ecb(), NULL, g_key, NULL);
        assert(ret == 1);

        ret = EVP_CIPHER_CTX_set_padding(des_ctx, 0);
        assert(ret == 1);

        uint8_t *result_unciphered = malloc(in_sz * sizeof(uint8_t));
        int backl;

        ret = EVP_DecryptUpdate(des_ctx, result_unciphered, &backl, in, in_sz);
        assert(ret == 1);
        assert(backl == in_sz);
        tmp = backl;

        ret = EVP_DecryptFinal_ex(des_ctx, &result_unciphered[backl], &backl);
        assert(ret == 1);
        assert(backl == 0);
        backl += tmp;

        result->length = backl;
        result->result = result_unciphered;
    }

    return result;
}

void CAENC_CTX_new(Algorithm algo, uint8_t *key) {
    g_current_ctx_algo = algo;
    g_key = key;

    if (g_current_ctx_algo == EDES) {
        sbox_init(key);
    }
    else if (g_current_ctx_algo == DES) {
        des_ctx = EVP_CIPHER_CTX_new();
    }

    g_initialized = true;
}

void CAENC_CTX_cleanup() {
    if (des_ctx) {
        EVP_CIPHER_CTX_cleanup(des_ctx);
    }
}