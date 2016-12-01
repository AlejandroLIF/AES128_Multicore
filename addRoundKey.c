#include "addRoundKey.h"
#include "AES128.h"
#include <x86intrin.h>

void addRoundKey(unsigned char* const block, const unsigned char* const key){
    unsigned char* a = block;
    const unsigned char* b = key;
    int i;
    __m128i aVec;
    __m128i bVec;
    __m128i res;
    if (INSTRINSICS_ENABLED) {
      aVec = _mm_load_si128((__m128i*)a);
      bVec = _mm_load_si128((__m128i*)b);
      res  = _mm_xor_si128 (aVec, bVec);
      _mm_store_si128((__m128i*)a, res);
    }
    else {
      for(i = 0; i < BLOCK_SIZE; i++){
          *a = (*a)^(*(b++));
          a++;
      }
    }
}
