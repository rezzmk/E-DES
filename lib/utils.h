#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

/*
Reads a file as bytes
*/
uint8_t *read_file_bytes(char *file_name, uint64_t *file_length);
/*
Writes a buffer to a file
*/
void write_file_bytes(uint8_t *buffer, uint64_t sz, char *file_name);

#endif