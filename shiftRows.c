#include "shiftRows.h"

void shiftRows(unsigned char* const block){
    unsigned char temp;
    //Shift first row
    temp = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = temp;
    
    //Shift second row
    temp = block[2];
    block[2] = block[10];
    block[10] = temp;
    temp = block[6];
    block[6] = block[14];
    block[14] = temp;
    
    //Shift third row
    temp = block[3];
    block[3] = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = temp;
}

void invShiftRows(unsigned char* const block){
    unsigned char temp;
    //Shift first row
    temp = block[13];
    block[13] = block[9];
    block[9] = block[5];
    block[5] = block[1];
    block[1] = temp;
    
    //Shift second row
    temp = block[14];
    block[14] = block[6];
    block[6] = temp;
    temp = block[10];
    block[10] = block[2];
    block[2] = temp;
    
    //Shift third row
    temp = block[7];
    block[7] = block[11];
    block[11] = block[15];
    block[15] = block[3];
    block[3] = temp;
}
