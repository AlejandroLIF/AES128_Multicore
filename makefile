CC=gcc
ARGS=-O

all: AES128.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o
	$(CC) $(ARGS) -o AES128.run AES128.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o

addRoundKey.o : addRoundKey.c
	$(CC)  -c -Wall addRoundKey.c addRoundKey.h
	
AES128.o : AES128.c
	$(CC)  -c -Wall AES128.c AES128.h
	
keyExpansion.o : keyExpansion.c
	$(CC)  -c -Wall keyExpansion.c
	
mixColumns.o : mixColumns.c
	$(CC)  -c -Wall mixColumns.c
	
rotateWord.o : rotateWord.c
	$(CC)  -c -Wall rotateWord.c
	
shiftRows.o : shiftRows.c
	$(CC)  -c -Wall shiftRows.c
	
subBytes.o : subBytes.c
	$(CC)  -c -Wall subBytes.c

test: AES128_test.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o
	$(CC) $(ARGS) -o AES128_test.run AES128_test.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o
    
AES128_test.o : AES128_test.c
	$(CC) -c -Wall AES128_test.c
        
clean:
	rm *.o
