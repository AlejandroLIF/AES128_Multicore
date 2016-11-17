#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES128.h"

#include "addRoundKey.h"
#include "subBytes.h"
#include "shiftRows.h"
#include "mixColumns.h"
#include "keyExpansion.h"

#define showTextStatus do{ for(i = 0; i<4; i++){\
                                for(j = 0; j<4; j++){\
                                    printf("%02x ", plainText[4*j + i]);        \
                                }\
                                printf("\r\n");\
                            }\
                            printf("\r\n");\
                            }\
                        while(0);

/*
  Reference document: http://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf
*/

int main(int argc, char *argv[]){
    unsigned char keyArray[176] = {"Thats my Kung Fu"};
    unsigned char plainText[16] = {"Two One Nine Two"};
    int roundNum, keyIndex, i, j;
    for(i = 0; i<16; i++){
        printf("%02x ", plainText[i]);
    }
    printf("\r\n");
    
    keyIndex = 0;
    expand(&keyArray[0]); //Verified key expansion
    
    //Begin Encryption
    showTextStatus;
    addRoundKey(&plainText[0], &keyArray[(keyIndex++) * BLOCK_SIZE]);
    showTextStatus;
    
    for(roundNum = 0; roundNum<9; roundNum++){
        subBytes(&plainText[0], BLOCK_SIZE);
        showTextStatus;
        shiftRows(&plainText[0]);
        showTextStatus;
        mixColumns(&plainText[0]);
        showTextStatus;
        addRoundKey(&plainText[0], &keyArray[(keyIndex++) * BLOCK_SIZE]);
        showTextStatus;
    }
    
    subBytes(&plainText[0], BLOCK_SIZE);
    showTextStatus;
    shiftRows(&plainText[0]);
    showTextStatus;
    addRoundKey(&plainText[0], &keyArray[(keyIndex++) * BLOCK_SIZE]);
    showTextStatus;
    //End Encryption
    
    //Begin Decryption
    keyIndex = 10;
    addRoundKey(plainText, &keyArray[(keyIndex--) * BLOCK_SIZE]); //Add round key and reduce the key index
    
    for(roundNum = 0; roundNum < 9; roundNum++){
        invShiftRows(plainText);
        invSubBytes(plainText, BLOCK_SIZE);
        addRoundKey(plainText, &keyArray[(keyIndex--) * BLOCK_SIZE]);
        invMixColumns(plainText);
    }
    
    invShiftRows(plainText);
    invSubBytes(plainText, BLOCK_SIZE);
    addRoundKey(plainText, &keyArray[(keyIndex--) * BLOCK_SIZE]);
    showTextStatus;
    //End Decryption
    
    for(i = 0; i<16; i++){
        printf("%02x ", plainText[i]);
    }
    printf("\r\n");
    return 0;
}
