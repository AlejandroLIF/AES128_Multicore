#ifndef AES128_H
#define AES128_H

#define BLOCK_SIZE 16
#define KEY_ARRAY_SIZE 176
#define WORD_SIZE 4

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#include "addRoundKey.h"
#include "subBytes.h"
#include "shiftRows.h"
#include "mixColumns.h"
#include "keyExpansion.h"

typedef struct{
    unsigned char* data;
    unsigned char* keyArray;
    long length;
    long *nextByte;
    pthread_mutex_t* mutex;
} threadInfo_t;

int main(int argc, char* argv[]);
void encryptFile(char* inputFileName, char* outputFileName, char* key);
void* encryptFile_thread(void* p);
void encryptBlock(unsigned char* const block, const unsigned char* const expandedKey);
void decryptFile(char* inputFileName, char* outputFileName, char* key);
void* decryptFile_thread(void* p);
void decryptBlock(unsigned char* const block, const unsigned char* const expandedKey);
void parseKey(char* key, unsigned char* const keyArray);

#endif
