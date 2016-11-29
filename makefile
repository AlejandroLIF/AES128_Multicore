CC=gcc
CCXFLAGS=-msse2 -ggdb
ARGS=-O

all: AES128.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o
	$(CC) $(ARGS) -o AES128.run AES128.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o

addRoundKey.o : addRoundKey.c
	$(CC) -c $(CCXFLAGS) -Wall addRoundKey.c addRoundKey.h
	
AES128.o : AES128.c
	$(CC)  -c $(CCXFLAGS) -Wall AES128.c AES128.h
	
keyExpansion.o : keyExpansion.c
	$(CC)  -c $(CCXFLAGS) -Wall keyExpansion.c
	
mixColumns.o : mixColumns.c
	$(CC)  -c $(CCXFLAGS) -Wall mixColumns.c
	
rotateWord.o : rotateWord.c
	$(CC)  -c $(CCXFLAGS) -Wall rotateWord.c
	
shiftRows.o : shiftRows.c
	$(CC)  -c  $(CCXFLAGS) -Wall shiftRows.c
	
subBytes.o : subBytes.c
	$(CC)  -c  $(CCXFLAGS) -Wall  subBytes.c

test: AES128_test.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o
	$(CC) $(ARGS) -o AES128_test.run AES128_test.o addRoundKey.o keyExpansion.o mixColumns.o rotateWord.o shiftRows.o subBytes.o
    
AES128_test.o : AES128_test.c
	$(CC) -c -Wall AES128_test.c
        
clean:
	rm *.o
