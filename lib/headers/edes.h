#ifndef _EDES_H
#define _EDES_H

#include <stdint.h>

#define BLOCK_HALF_SIZE (BLOCK_SIZE_BYTES / 2)

#define SBOX_SIZE 256
#define BLOCK_SIZE_BYTES 8
#define NUM_SBOXES 16
#define KEY_SIZE 256
#define KEY_SIZE_BYTES (KEY_SIZE / 8)
#define BLOCK_HALF_SIZE (BLOCK_SIZE_BYTES / 2)

/*
E-DES Encryption result
*/
typedef struct {
    uint8_t *original;
    uint8_t *encrypted;
    uint64_t encrypted_len;
} EDES_Result;

/*
E-DES Decryption result
*/
typedef struct {
    uint8_t *cipher_text;
    uint8_t *message;
    uint64_t message_len;
} EDES_Decryption;

/*
Unpads a buffer, using PKCS#7
*/
extern uint8_t *unpad(uint8_t *input, uint64_t input_len, uint8_t block_sz, uint64_t *padded_size);
/*
Pads a buffer, using PKCS#7
*/
extern uint8_t *pad(uint8_t *input, uint64_t input_len, uint8_t block_sz, uint64_t *padded_size);
/*
Encrypts a buffer
*/
extern EDES_Result *edes_encrypt(uint8_t *input, uint64_t file_len, uint8_t *key);
/*
Decrypts a buffer
*/
extern EDES_Decryption *edes_decrypt(uint8_t *input, uint64_t len, uint8_t *key);
/*
Encrypts a file
*/
extern EDES_Result *encrypt_file(char *file_name, char *key_str);
/*
Decrypts a file
*/
extern EDES_Decryption *decrypt_file(char *file_name, char *key_str);
/*
Processes a block for decryption
*/
extern void process_block_inverse(uint8_t block[BLOCK_SIZE_BYTES], uint8_t result_block[BLOCK_SIZE_BYTES], uint8_t sboxes[NUM_SBOXES][SBOX_SIZE]);
/*
Processes a block for encryption
*/
extern void process_block(uint8_t block[BLOCK_SIZE_BYTES], uint8_t result_block[BLOCK_SIZE_BYTES], uint8_t sboxes[NUM_SBOXES][SBOX_SIZE]);
/*
Generates an S-Box, given a key and it's index
*/
extern void gen_sbox(uint8_t sbox[], uint8_t *key, uint8_t sbox_idx);
/*
Initializes the S-Box, given a key. This will call gen_sbox()
*/
extern void sbox_init(uint8_t *key);

#endif
