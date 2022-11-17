#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "edes.h"
#include "utils.h"
#include <pthread.h>

uint8_t sboxes[NUM_SBOXES][SBOX_SIZE];
bool initialized = false;

uint8_t *pad(uint8_t *input, uint64_t input_len, uint8_t block_sz, uint64_t *padded_size) {
	// Calculate the padding value.
	// - If the input length is a multiple of block size (8), we add another full block with value 8.
	// - Otherwise, we calculate the number of bytes needed to get to the desired size, 
	//   e.g. a 7 byte input will turn into a 8 byte padded input, with value 1 at the end.
	uint8_t pad_value = 0;
	if (input_len % block_sz == 0) {
		pad_value = block_sz;
	}
	else {
		pad_value = block_sz - (input_len % block_sz);
	}

	uint64_t final_size = input_len + pad_value;

	// Allocate new memory to accomodate the extra bytes, copy existent data and set the padded bytes
	uint8_t *padded_result = (uint8_t*) malloc(final_size);
	memcpy(padded_result, input, input_len);
	for (uint8_t i = 0; i < pad_value; i++) {
		padded_result[input_len + i] = pad_value;
	}

	*padded_size = final_size;
	return padded_result;
}

uint8_t *unpad(uint8_t *input, uint64_t input_len, uint8_t block_sz, uint64_t *padded_size) {
	// On PKCS#7, all we need to do to unpad is check last byte's value and remove that number of bytes
	// e.g. last value is 8, we remove the last 8 bytes
	uint8_t pad_value = input[input_len - 1];
	uint64_t final_size = input_len - pad_value;

	// TODO(Marcos): Most likely there's no need to allocate new memory here, just provide the unpadded size
	//               and cap any accesses to it.
	uint8_t *unpadded_result = (uint8_t*) malloc(final_size);
	memcpy(unpadded_result, input, final_size);

	*padded_size = final_size;
	return unpadded_result;
}

EDES_Result *encrypt_file(char *file_name, char *key_str) {
    uint64_t file_length = 0;
    uint8_t *buffer = read_file_bytes(file_name, &file_length);
    uint8_t *key = get_sha_256(key_str);

    EDES_Result *cipher = edes_encrypt(buffer, file_length, key);
	return cipher;
}

EDES_Decryption *decrypt_file(char *file_name, char *key_str) {
    uint64_t file_length = 0;
    uint8_t *buffer = read_file_bytes(file_name, &file_length);
    uint8_t *key = get_sha_256(key_str);

    EDES_Decryption *cipher = edes_decrypt(buffer, file_length, key);
	return cipher;
}

EDES_Result *edes_encrypt(uint8_t *input, uint64_t file_len, uint8_t *key) {
	// Check if context has already been initialized, if not, generate the sboxes
	if (!initialized) sbox_init(key);

	EDES_Result *result = (EDES_Result*) malloc(sizeof(EDES_Result));
	result->original = input;

	uint8_t *padded_result = pad(input, file_len, BLOCK_SIZE_BYTES, &result->encrypted_len);
	uint8_t *cipher_result = calloc(result->encrypted_len, sizeof(uint8_t));

	for (uint32_t i = 0; i < result->encrypted_len / BLOCK_SIZE_BYTES; i++) {
		process_block(padded_result + (i * BLOCK_SIZE_BYTES), cipher_result + (i * BLOCK_SIZE_BYTES), sboxes);
	}

	// We don't need the padded message anymore, not freeing this will leak memory
	free(padded_result);

	result->encrypted = cipher_result;

	return result;
}

EDES_Decryption *edes_decrypt(uint8_t *input, uint64_t len, uint8_t *key) {
	// Check if context has already been initialized, if not, generate the sboxes
	if (!initialized) sbox_init(key); 

	uint64_t num_blocks = len / BLOCK_SIZE_BYTES;

	uint8_t *message = calloc(len, sizeof(uint8_t));
	for (int i = 0; i < num_blocks; i++) {
		process_block_inverse(input + (i * BLOCK_SIZE_BYTES), message + (i * BLOCK_SIZE_BYTES), sboxes);
	}

	EDES_Decryption *result = (EDES_Decryption*) malloc(sizeof(EDES_Decryption));
	result->cipher_text = input;

	uint8_t *unpadded_result = unpad(message, len, BLOCK_SIZE_BYTES, &result->message_len);
	result->message = unpadded_result;

	// We don't need the message anymore, not freeing this will leak memory
	free(message);

	return result;
}

void process_block_inverse(uint8_t block[BLOCK_SIZE_BYTES], uint8_t result_block[BLOCK_SIZE_BYTES], uint8_t sboxes[NUM_SBOXES][SBOX_SIZE]) {
	uint8_t left[BLOCK_HALF_SIZE] = {block[0], block[1], block[2], block[3]};
	uint8_t right[BLOCK_HALF_SIZE] = {block[4], block[5], block[6], block[7]};

	uint8_t output[BLOCK_HALF_SIZE];
	uint8_t right_tmp[BLOCK_HALF_SIZE];
	for (int i = NUM_SBOXES - 1; i >= 0; i--) {
		for (int i = 0; i < BLOCK_HALF_SIZE; i++) {
			right_tmp[i] = right[i];
			right[i] = left[i];
			output[i] = 0;
		}

		int index = left[0]; 
		output[3] = sboxes[i][index];
		index = (index + left[1]) % SBOX_SIZE; 
		output[2] = sboxes[i][index];
		index = (index + left[2]) % SBOX_SIZE; 
		output[1] = sboxes[i][index];
		index = (index + left[3]) % SBOX_SIZE; 
		output[0] = sboxes[i][index];

		for (int i = 0; i < BLOCK_HALF_SIZE; i++) {
			left[i] = right_tmp[i] ^ output[i];
		}

		for (int i = 0; i < BLOCK_SIZE_BYTES; i++) {
			result_block[i] = i < BLOCK_HALF_SIZE ? left[i] : right[i - BLOCK_HALF_SIZE];
		}
	}
}

void process_block(uint8_t block[BLOCK_SIZE_BYTES], uint8_t result_block[BLOCK_SIZE_BYTES], uint8_t sboxes[NUM_SBOXES][SBOX_SIZE]) {
	uint8_t left[BLOCK_HALF_SIZE] = {block[0], block[1], block[2], block[3]};
	uint8_t right[BLOCK_HALF_SIZE] = {block[4], block[5], block[6], block[7]};

	uint8_t output[BLOCK_HALF_SIZE];
	uint8_t left_tmp[BLOCK_HALF_SIZE];
	for (int i = 0; i < NUM_SBOXES; i++) {
		for (int i = 0; i < BLOCK_HALF_SIZE; i++) {
			left_tmp[i] = left[i];
			left[i] = right[i];
			output[i] = 0;
		}

		int index = right[0]; 
		output[3] = sboxes[i][index];
		index = (index + right[1]) % SBOX_SIZE; 
		output[2] = sboxes[i][index];
		index = (index + right[2]) % SBOX_SIZE; 
		output[1] = sboxes[i][index];
		index = (index + right[3]) % SBOX_SIZE; 
		output[0] = sboxes[i][index];

		for (int i = 0; i < BLOCK_HALF_SIZE; i++) {
			right[i] = left_tmp[i] ^ output[i];
		}

		for (int i = 0; i < BLOCK_SIZE_BYTES; i++) {
			result_block[i] = i < BLOCK_HALF_SIZE ? left[i] : right[i - BLOCK_HALF_SIZE];
		}
	}
}

void sbox_init(uint8_t *key) {
	initialized = true;
	for (int i = 0; i < NUM_SBOXES; i++) {
		for (int j = 0; j < SBOX_SIZE; j++) {
			sboxes[i][j] = j;
		}
		gen_sbox(sboxes[i], key, i);
	}
}

void gen_sbox(uint8_t sbox[], uint8_t *key, uint8_t sbox_idx) {
	if (sbox_idx > 0) {
		for(int i = 0; i < KEY_SIZE_BYTES - 1; i++) {
			key[i] = key[i + 1] ^ sbox_idx;
		}
	}

	uint8_t j = 0; // initial value
	uint8_t key_sum = 0;
	for(int i = 0; i < KEY_SIZE_BYTES; i++) {
		key_sum += key[i] % SBOX_SIZE;
	}
	j = key_sum;

	uint8_t k = 0;
	uint8_t tmp = 0;
	for (int i = 0; i < SBOX_SIZE; i++) {
		k = (sbox[i] + sbox[j]) % KEY_SIZE_BYTES;
		j = (j + key[k]) % SBOX_SIZE;

		// Swap sbox[i] with sbox[j]
		tmp = sbox[i];
		sbox[i] = sbox[j];
		sbox[j] = tmp;
	}
}
