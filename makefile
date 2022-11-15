LIB_FILE_NAME = libedes.a
OBJ_DIR = ./lib

all: lib/libedes.a encrypt decrypt speed clean

# Static EDES library build
lib/libedes.a: utils.o edes.o caencryption.o
	ar -rcs $@ $^

edes.o: lib/edes.h lib/utils.h
	gcc -c lib/edes.c lib/utils.c -O3

utils.o: lib/utils.h
	gcc -c lib/utils.c -O3

caencryption.o: lib/edes.h
	gcc -c lib/caencryption.c lib/edes.c -O3

# Encryption programs build
encrypt:
	gcc encrypt.c -I./lib -L./lib -ledes -lpthread -lcrypto -o encrypt -O3

decrypt:
	gcc decrypt.c -I./lib -L./lib -ledes -lpthread -lcrypto -o decrypt -O3

# Benchmarks
speed:
	gcc speed.c -o speed -I./lib -L./lib -ledes -lcrypto -lpthread -O3

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