#ifndef _UTILS_H
#define _UTILS_H

#include <stdint.h>
#include <stddef.h>

/*
boolean definition, no need for #include <bool.h> as we're only using this for very simple state handling
*/
typedef enum { false, true } bool;

/*
Reads a file as bytes
*/
extern uint8_t *read_file_bytes(char *file_name, uint64_t *file_length);
/*
Writes a buffer to a file
*/
extern void write_file_bytes(uint8_t *buffer, uint64_t sz, char *file_name);
/*
Gets the SHA256 hash of an input
*/
extern uint8_t *get_sha_256(char *input);

#endif