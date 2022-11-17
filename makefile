LIB_FILE_NAME = libedes.a
OBJ_DIR = ./lib

all: lib/libedes.a encrypt decrypt speed clean

# Static EDES library build
lib/libedes.a: utils.o edes.o crypto.o
	ar -rcs $@ $^

edes.o: lib/headers/edes.h lib/headers/utils.h
	gcc -c -I./lib/headers lib/edes.c lib/utils.c -O3

utils.o: lib/headers/utils.h
	gcc -c -I./lib/headers lib/utils.c -O3

crypto.o: lib/headers/edes.h
	gcc -c -I./lib/headers lib/crypto.c lib/edes.c -O3

# Encryption programs build
encrypt:
	gcc encrypt.c -I./lib/headers -L./lib -ledes -lpthread -lcrypto -o encrypt -O3

decrypt:
	gcc decrypt.c -I./lib/headers -L./lib -ledes -lpthread -lcrypto -o decrypt -O3

# Benchmarks
speed:
	gcc speed.c -o speed -I./lib/headers -L./lib -ledes -lcrypto -lpthread -O3

# Cleanup
clean:
	rm -f ./*.o
	rm -f ./lib/*.o

cleanall:
	rm -f ./*.o
	rm -f ./lib/*.o
	rm encrypt
	rm decrypt
	rm speed
