#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES128.h"

#include "addRoundKey.h"
#include "subBytes.h"
#include "shiftRows.h"
#include "mixColumns.h"
#include "keyExpansion.h"


void encryptFile(char* fileName, char* key);
void encryptBlock(unsigned char* const block, const unsigned char* const expandedKey);
void decryptFile(char* fileName, char* key);
void decryptBlock(unsigned char* const block, const unsigned char* const expandedKey);
void parseKey(char* key, unsigned char* const keyArray);

int main(int argc, char *argv[]){
    if(argc != 4){
        IO_ERR: printf("Usage: %s [-encrypt|-decrypt] [file] [32-char HEX Key | 16-char ASCII Key]\r\n", argv[0]);
        printf("Example: %s -encrypt myFile.txt 00112233445566778899AABBCCDDEEFF\r\n", argv[0]);
        printf("Example: %s -decrypt encrypted.bin 12345TheKey12345\r\n", argv[0]);
        return -1;
    }
    else{
        if(strcmp(argv[1], "-encrypt") == 0){
            encryptFile(argv[2], argv[3]);
        }
        else if(strcmp(argv[1], "-decrypt") == 0){
            decryptFile(argv[2], argv[3]);
        }
        else{
            goto IO_ERR;
        }
    }
    return 0;
}

void encryptFile(char* fileName, char* key){
    unsigned char keyArray[176]; //keyArray should hold enough memory for the expanded key
    unsigned char data[BLOCK_SIZE];
    unsigned char bytesRead;
    int i;
    parseKey(key, keyArray);
    expand(&keyArray[0]);
    
    FILE *ifp = fopen(fileName, "rb");
    if(ifp == NULL){
        printf("ERROR: invalid input file\r\n");
        exit(-1);//Cannot continue
    }
    
    FILE *ofp = fopen("AES128_encrypted_output", "wb");
    if(ifp == NULL){
        printf("ERROR: unable to write output to AES128_encrypted_output\r\n");
        fclose(ifp);
        exit(-1);//Cannot continue
    }
    
    do{
        memset(&data[0], 0, BLOCK_SIZE); //Make sure "data" holds all zeroes.
        bytesRead = fread(&data[0], 1, BLOCK_SIZE, ifp);
        
        if(bytesRead < BLOCK_SIZE){ //The last block may require padding
            for(i = 0; i < BLOCK_SIZE - bytesRead; i++){
                data[BLOCK_SIZE - 1 - i] = BLOCK_SIZE - bytesRead;
            }
        }
        
        encryptBlock(&data[0], &keyArray[0]);
        fwrite(&data[0], 1, BLOCK_SIZE, ofp);
    }while(bytesRead == BLOCK_SIZE); //Read until EOF
    
    fclose(ifp);
    fclose(ofp);
}

void encryptBlock(unsigned char* const block, const unsigned char* const expandedKey){
    int keyIndex = 0;
    int i;
    
    addRoundKey(block, &expandedKey[(keyIndex++) * BLOCK_SIZE]); //Add round key and increase the key index.

    for(i = 0; i<9; i++){
        subBytes(block, BLOCK_SIZE);
        shiftRows(block);
        mixColumns(block);
        addRoundKey(block, &expandedKey[(keyIndex++) * BLOCK_SIZE]);
    }

    subBytes(block, BLOCK_SIZE);
    shiftRows(block);
    addRoundKey(block, &expandedKey[(keyIndex++) * BLOCK_SIZE]);
}

void decryptFile(char* fileName, char* key){
    unsigned char keyArray[176];
    unsigned char data[BLOCK_SIZE];
    unsigned char bytesRead;
    int i;
    unsigned char paddingBytes;
    parseKey(key, keyArray);
    expand(&keyArray[0]);
    
    FILE *ifp = fopen(fileName, "rb");
    if(ifp == NULL){
        printf("ERROR: invalid input file\r\n");
        exit(-1);//Cannot continue
    }
    
    FILE *ofp = fopen("AES128_decrypted_output", "wb");
    if(ifp == NULL){
        printf("ERROR: unable to write output to AES128_decrypted_output\r\n");
        fclose(ifp);
        exit(-1);//Cannot continue
    }
    
    do{
        memset(&data[0], 0, BLOCK_SIZE); //Make sure "data" holds all zeroes.
        bytesRead = fread(&data[0], 1, BLOCK_SIZE, ifp);
        decryptBlock(&data[0], &keyArray[0]);
        
        paddingBytes = data[BLOCK_SIZE - 1];
        //TODO: THE CASE WHEN ONLY 1 PADDING BYTE IS ADDED IS NOT BEING HANDLED!
        if(paddingBytes < BLOCK_SIZE && paddingBytes > 1){ //This may be the last block.
            for(i = 0; i < paddingBytes; i++){
                if(data[BLOCK_SIZE - 1 - i] != paddingBytes){
                    break;
                }
            }
            if(i == paddingBytes){
                bytesRead = BLOCK_SIZE - paddingBytes;
            }
        }
        fwrite(&data[0], 1, bytesRead, ofp);
    }while(bytesRead == BLOCK_SIZE); //Read until EOF
    
    fclose(ifp);
    fclose(ofp);
}

void decryptBlock(unsigned char* const block, const unsigned char* const expandedKey){
    int keyIndex = 10;
    int i;
    
    addRoundKey(block, &expandedKey[(keyIndex--) * BLOCK_SIZE]); //Add round key and reduce the key index
    
    for(i = 0; i < 9; i++){
        invShiftRows(block);
        invSubBytes(block, BLOCK_SIZE);
        addRoundKey(block, &expandedKey[(keyIndex--) * BLOCK_SIZE]);
        invMixColumns(block);
    }
    
    invShiftRows(block);
    invSubBytes(block, BLOCK_SIZE);
    addRoundKey(block, &expandedKey[(keyIndex--) * BLOCK_SIZE]);
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
