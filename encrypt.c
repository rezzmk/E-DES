#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "utils.h"
#include "crypto.h"

#define MAX_BUF_SIZE 4096

void print_buf(uint8_t *buf, size_t buf_len);
void print_help();
uint8_t *try_read_from_stdin(uint64_t *size);

int main(int argc, char **args) {
   int option;

   uint8_t *key_str = NULL;
   uint8_t *file_name = NULL;
   uint8_t *output_file = NULL;
   bool legacy = false;

   while ((option = getopt(argc, args, ":k:f:m:o:l:h")) != -1) {
      switch (option) {
      case 'f':
         file_name = optarg;
         break;
      case 'k':
         key_str = optarg;
         break;
      case 'o':
         output_file = optarg;
         break;
      case 'l':
         printf("using legacy DES\n");
         legacy = true;
         break;
      case 'h':
         print_help();
         return 0;
      case ':':
         printf("option needs a value\n");
         break;
      case '?':
         printf("unknown option: %c \n", optopt);
         break;
      }
   }

   bool ok = true;
   if (key_str == NULL) {
      printf("\nThe following options are missing: \n-k (key)\n");
      ok = false;
   }

   uint64_t file_length = 0;
   uint8_t *stdin_input = try_read_from_stdin(&file_length);
   if (file_name == NULL && stdin_input == NULL) {
      printf("-f (input file name). You can also use input redirection with '<'\n");
      ok = false;
   }
   if (!ok) {
      printf("\n\n");
      print_help();
      return 1;
   }

   uint8_t *buffer = stdin_input != NULL ? stdin_input : read_file_bytes(file_name, &file_length);
   uint8_t *key = get_sha_256(key_str);

   Algorithm algo = EDES;
   if (legacy) { 
      algo = DES;
   }

   printf("Encrypting with %s...\n", algo == DES ? "DES" : "EDES");
   CAENC_CTX_new(algo, key);
   
   ENCRYPTION_RESULT *encryption_result = encrypt(buffer, file_length);

   if (output_file != NULL) {
      write_file_bytes(encryption_result->result, encryption_result->length, output_file);
   } else {
      if (encryption_result->length > 256) {
         printf("Printing first 256 bytes of result, saving everything to c-enc\n\n\tCiphertext (in bytes): ");
         write_file_bytes(encryption_result->result, encryption_result->length, "c-enc");
         print_buf(encryption_result->result, 256);
      }
      else {
         print_buf(encryption_result->result, encryption_result->length);
      }
   }

   CAENC_CTX_cleanup();
   return 0;
}

void print_buf(uint8_t *buf, size_t buf_len) {
   for (int i = 0; i < buf_len; i++) {
      printf("%x ", buf[i]);
   }
   printf("\n");
}

void print_help() {
   printf("Options:\n");
   printf("\t-f {input file name}\n");
   printf("\t-o {output file name}\n");
   printf("\t-k {key string}\n");
   printf("\t-l (if set, DES will be used, instead of E-DES)\n");
}

uint8_t *try_read_from_stdin(uint64_t *size) {
   if (!isatty(STDIN_FILENO)) {
      uint8_t *buffer = 0;
      uint64_t n = 0;
      uint32_t current_ch; // EOF represented by more than 1 char

      do {
         buffer = (uint8_t*) realloc(buffer, n + 1);
         current_ch = fgetc(stdin);
         buffer[n] = current_ch;
         if (current_ch != EOF) {
            n++;
         }
      }
      while (current_ch != EOF);

      *size = n;
      return buffer;
   }

   return NULL;
}
