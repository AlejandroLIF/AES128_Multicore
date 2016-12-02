CC=gcc
ARGS=-O -pthread

all: AES128.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o
	$(CC) $(ARGS) -o AES128.run AES128.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o

addRoundKey.o : addRoundKey.c
	$(CC) $(ARGS)  -c -Wall addRoundKey.c addRoundKey.h

AES128.o : AES128.c
	$(CC) $(ARGS)  -c -Wall AES128.c AES128.h

keyExpansion.o : keyExpansion.c
	$(CC) $(ARGS)  -c -Wall keyExpansion.c

mixColumns.o : mixColumns.c
	$(CC) $(ARGS)  -c -Wall mixColumns.c

rotateWord.o : rotateWord.c
	$(CC) $(ARGS)  -c -Wall rotateWord.c

shiftRows.o : shiftRows.c
	$(CC) $(ARGS)  -c -Wall shiftRows.c

subBytes.o : subBytes.c
	$(CC) $(ARGS)  -c -Wall subBytes.c

test: AES128_test.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o
	$(CC) $(ARGS) -o AES128_test.run AES128_test.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o

AES128_test.o : AES128_test.c
	$(CC)  $(ARGS) -c -Wall AES128_test.c

clean:
	rm *.o
	rm *.run
	rm *.gch
