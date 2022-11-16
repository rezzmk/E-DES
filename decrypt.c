
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "caencryption.h"
#include "utils.h"
#include "edes.h"

#define MAX_BUF_SIZE 4096

void print_buf(uint8_t *buffer, size_t sz) {
   for (uint32_t i = 0; i < sz; i++) {
      printf("%x ", buffer[i]);
   }
   printf("\n");
}

int main(int argc, char **args) {
   int option;

   uint8_t *key_str;
   uint8_t *file_name;
   uint8_t *output_file;
   bool legacy = false;

   while ((option = getopt(argc, args, ":k:f:m:o:l")) != -1) {
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
      printf("The following options are missing: \n-k (key)\n");
      ok = false;
   }

   if (file_name == NULL) {
      printf("-f (input file name)\n");
      ok = false;
   }
   if (!ok) return 1;

   uint64_t file_length = 0;
   uint8_t *buffer = read_file_bytes(file_name, &file_length);
   uint8_t *key = get_sha_256(key_str);

   Algorithm algo = EDES;
   if (legacy) { 
      algo = DES;
   }

   printf("Decrypting with %s...\n", algo == DES ? "DES" : "EDES");
   CAENC_CTX_new(algo, key);
   
   ENCRYPTION_RESULT *encryption_result = decrypt(buffer, file_length);

   if (output_file != NULL) {
      write_file_bytes(encryption_result->result, encryption_result->length, output_file);
   }

   CAENC_CTX_cleanup();

   return 0;
}
