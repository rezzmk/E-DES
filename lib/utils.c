#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <openssl/sha.h>

#include "utils.h"

void write_file_bytes(uint8_t *buffer, uint64_t sz, char *file_name) {
    FILE *file;
    file = fopen(file_name, "w");
    fwrite(buffer, sz, 1, file);
    fclose(file);
}

uint8_t *read_file_bytes(char *file_name, uint64_t *file_length) {
    FILE *file;
    size_t file_sz;
    uint8_t *buffer;

    // TODO(Marcos): validations
    file = fopen(file_name, "rb");

    fseek(file, 0, SEEK_END);
    file_sz = ftell(file);

    rewind(file);

    buffer = (uint8_t*) malloc(file_sz * sizeof(uint8_t));
    uint64_t read_bytes = fread(buffer, file_sz, 1, file);
    fclose(file);

    *file_length = file_sz;
    return buffer;
}

uint8_t *get_sha_256(char *input) {
    uint8_t *key = calloc(32, sizeof(uint8_t));
    key = SHA256(input, strlen(input), NULL);
    return key;
}