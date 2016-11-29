#ifndef AES128_H
#define AES128_H

#define BLOCK_SIZE 16
#define WORD_SIZE 4
#define INSTRINSICS_ENABLED 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "addRoundKey.h"
#include "subBytes.h"
#include "shiftRows.h"
#include "mixColumns.h"
#include "keyExpansion.h"

int main(int argc, char* argv[]);
void encryptFile(char* inputFileName, char* outputFileName, char* key);
void encryptBlock(unsigned char* const block, const unsigned char* const expandedKey);
void decryptFile(char* inputFileName, char* outputFileName, char* key);
void decryptBlock(unsigned char* const block, const unsigned char* const expandedKey);
void parseKey(char* key, unsigned char* const keyArray);


#endif
