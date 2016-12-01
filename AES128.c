#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES128.h"

#include "addRoundKey.h"
#include "subBytes.h"
#include "shiftRows.h"
#include "mixColumns.h"
#include "keyExpansion.h"
#include <time.h>
#include "wmmintrin.h"

int main(int argc, char *argv[]){
    clock_t begin, end;
    begin = clock();
    if(argc != 5){
        IO_ERR: printf("Usage: %s [-encrypt|-decrypt] [input file] [output file] [32-char HEX Key | 16-char ASCII Key]\r\n", argv[0]);
        printf("Example: %s -encrypt plaintext.txt encrypted.bin 00112233445566778899AABBCCDDEEFF\r\n", argv[0]);
        printf("Example: %s -decrypt encrypted.bin plaintext.txt 12345TheKey12345\r\n", argv[0]);
        return -1;
    }
    else{
        if(strcmp(argv[1], "-encrypt") == 0){
            encryptFile(argv[2], argv[3], argv[4]);
        }
        else if(strcmp(argv[1], "-decrypt") == 0){
            decryptFile(argv[2], argv[3], argv[4]);
        }
        else{
            goto IO_ERR;
        }
    }
    end = clock();
    double time_spent = 1000*((double)(end-begin))/CLOCKS_PER_SEC;
    printf("Total execution time: %8.3f milliseconds.\r\n", time_spent);
    return 0;
}

void encryptFile(char* inputFileName, char* outputFileName, char* key){
    unsigned char keyArray[176]; //keyArray should hold enough memory for the expanded key
    unsigned char data[BLOCK_SIZE];
    unsigned char bytesRead;
    int i;
    int padding;
    unsigned char done = 0;
    parseKey(key, keyArray);
    expand(&keyArray[0]);

    FILE *ifp = fopen(inputFileName, "rb");
    if(ifp == NULL){
        printf("ERROR: invalid input file\r\n");
        exit(-1);//Cannot continue
    }

    FILE *ofp = fopen(outputFileName, "wb");
    if(ifp == NULL){
         printf("ERROR: unable to write output to \"%s\"\r\n", outputFileName);
        fclose(ifp);
        exit(-1);//Cannot continue
    }

    do{
        memset(&data[0], 0, BLOCK_SIZE); //Make sure "data" holds all zeroes.
        bytesRead = fread(&data[0], 1, BLOCK_SIZE, ifp);
        if(bytesRead < BLOCK_SIZE){ //The last block may require padding
          padding = 0;
          if(bytesRead != 0){
            padding = BLOCK_SIZE - bytesRead;
            bytesRead = BLOCK_SIZE;
          }
          done = 1;
        }

        encryptBlock(&data[0], &keyArray[0]);
        fwrite(&data[0], 1, bytesRead, ofp);
    }while(!done); //Read until EOF

    //A block with padding information is appended.
    memset(&data[0], padding, BLOCK_SIZE);
    encryptBlock(&data[0], &keyArray[0]);
    fwrite(&data[0], 1, BLOCK_SIZE, ofp);

    fclose(ifp);
    fclose(ofp);
}

void encryptBlock(unsigned char* const block, const unsigned char* const key){
    unsigned char* a = block;
    const unsigned char* b = key;
    int i;

    __m128i aVec;
    __m128i bVec;
    __m128i res;
    
    
    aVec = _mm_load_si128((__m128i*)a);
    bVec = _mm_load_si128((__m128i*)b);
    
    for(i = 0; i<9; i++){
        res = _mm_aesenc_si128( aVec, bVec );
    }
    res = _mm_aesenclast_si128(aVec, bVec);
    
}


void decryptFile(char* inputFileName, char* outputFileName, char* key){
    unsigned char keyArray[176];
    unsigned char data[3][BLOCK_SIZE];
    unsigned char bytesRead;
    int i;
    unsigned char done = 0;
    parseKey(key, keyArray);
    expand(&keyArray[0]);

    FILE *ifp = fopen(inputFileName, "rb");
    if(ifp == NULL){
        printf("ERROR: invalid input file\r\n");
        exit(-1);//Cannot continue
    }

    FILE *ofp = fopen(outputFileName, "wb");
    if(ifp == NULL){
         printf("ERROR: unable to write output to \"%s\"\r\n", outputFileName);
        fclose(ifp);
        exit(-1);//Cannot continue
    }

    //Read the first two blocks of data and store them in memory
    bytesRead = fread(&data[1][0], 1, 2*BLOCK_SIZE, ifp);
    decryptBlock(&data[1][0], &keyArray[0]);
    decryptBlock(&data[2][0], &keyArray[0]);

    do{
        //Shift out the two previously read blocks.
        memcpy(&data[0][0], &data[1][0], 2*BLOCK_SIZE);

        bytesRead = fread(&data[2][0], 1, BLOCK_SIZE, ifp);
        decryptBlock(&data[2][0], &keyArray[0]);

        //If EOF has been reached
        if(bytesRead == 0){
            //The previously read block contains the number of padding bytes.
            bytesRead = BLOCK_SIZE - data[1][0];
            done = 1;
        }
        fwrite(&data[0][0], 1, bytesRead, ofp);
    }while(!done); //Read until EOF2

    fclose(ifp);
    fclose(ofp);
}

void decryptBlock(unsigned char* const block, const unsigned char* const key){
    unsigned char* a = block;
    const unsigned char* b = key;
    int i;

    __m128i aVec;
    __m128i bVec;
    
    
    aVec = _mm_load_si128((__m128i*)a);
    bVec = _mm_load_si128((__m128i*)b);
    
    for(i = 0; i<9; i++){
        _mm_aesdec_si128( aVec, bVec );

    }
    _mm_aesdeclast_si128(aVec, bVec);
}

/*
    Parse the key from its string representation to a byte array.
*/
void parseKey(char* key, unsigned char* const keyArray){
    char* temp = key;
    int i = 0;
    char substring[3] = {0, 0, 0};
    // Find the null terminator
    while(*temp){
        temp++;
        i++;
    }

    if(i == 32){ //32-char Hex KEY
        // Go through each byte
        for(i = 15; i >= 0; i--){
            // Cycle back two characters
            temp -= 2;
            memcpy(substring, temp, 2);
            keyArray[i] = (unsigned char) strtol(&substring[0], &key, 16);
        }
    }
    else if(i == 16){ //16-char plaintext key
        for(i = 0; i<16; i++){
        keyArray[i] = (unsigned char)key[i];
        }
    }
    else{
        printf("ERROR: Invalid key. Accepted lengths: 16-char plaintext or 32-char HEX. Input length: %i\r\n", i);
        exit(-1); //Cannot continue
    }
}
