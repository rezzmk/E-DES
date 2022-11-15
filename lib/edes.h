#ifndef EDES_H
#define EDES_H

#include <stdint.h>

#define BLOCK_HALF_SIZE (BLOCK_SIZE_BYTES / 2)

#define SBOX_SIZE 256
#define BLOCK_SIZE_BYTES 8
#define NUM_SBOXES 16
#define KEY_SIZE 256
#define KEY_SIZE_BYTES (KEY_SIZE / 8)
#define BLOCK_HALF_SIZE (BLOCK_SIZE_BYTES / 2)

typedef enum { false, true } bool;

typedef struct {
    uint8_t *original;
    uint8_t *encrypted;
    uint64_t encrypted_len;
} EDES_Result;

typedef struct {
    uint8_t *cipher_text;
    uint8_t *message;
    uint64_t message_len;
} EDES_Decryption;

extern EDES_Result *edes_encrypt(uint8_t *input, uint64_t file_len, uint8_t *key);
extern EDES_Decryption *edes_decrypt(uint8_t *input, uint64_t len, uint8_t *key);
extern EDES_Result *encrypt_file(char *file_name, char *key_str);
extern EDES_Decryption *decrypt_file(char *file_name, char *key_str);
extern void process_block_inverse(uint8_t block[BLOCK_SIZE_BYTES], uint8_t result_block[BLOCK_SIZE_BYTES], uint8_t sboxes[NUM_SBOXES][SBOX_SIZE]);
extern void process_block(uint8_t block[BLOCK_SIZE_BYTES], uint8_t result_block[BLOCK_SIZE_BYTES], uint8_t sboxes[NUM_SBOXES][SBOX_SIZE]);
extern void gen_sbox(uint8_t sbox[], uint8_t *key, uint8_t sbox_idx);
extern uint8_t *get_sha_256(char *input);
extern void sbox_init(uint8_t *key);

#endif
