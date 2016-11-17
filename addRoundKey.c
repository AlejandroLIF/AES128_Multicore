#include "addRoundKey.h"
#include "AES128.h"

void addRoundKey(unsigned char* const block, const unsigned char* const key){
    unsigned char* a = block;
    const unsigned char* b = key;
    int i;
    for(i = 0; i < BLOCK_SIZE; i++){
        *a = (*a)^(*(b++));
        a++;
    }
}
