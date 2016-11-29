#include "AES128.h"

int main(int argc, char *argv[]){
    if(argc != 5){
        IO_ERR: printf("Usage: %s [-encrypt|-decrypt] [input file] [output file] [32-char HEX Key | 16-char ASCII Key]\r\n", argv[0]);
        printf("Example: %s -encrypt plaintext.txt encrypted.bin 00112233445566778899AABBCCDDEEFF\r\n", argv[0]);
        printf("Example: %s -decrypt encrypted.bin plaintext.txt 12345TheKey12345\r\n", argv[0]);
        return -1;
    }
    else{
        printf("%s\r\n%s\r\n%s\r\n", argv[2], argv[3], argv[4]);
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
    return 0;
}

void encryptFile(char* inputFileName, char* outputFileName, char* key){
    unsigned char keyArray[KEY_ARRAY_SIZE]; //keyArray should hold enough memory for the expanded key
    long fileSize;
    int padding;
    unsigned char *data;
    unsigned char bytesRead;
    int i;

    //Multithread variables
    const int NUM_CORES = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t *threads = (pthread_t*)malloc(NUM_CORES*sizeof(pthread_t));
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    threadInfo_t threadInfo;
    long nextByte;

    parseKey(key, keyArray);
    expand(&keyArray[0]);

    FILE *ifp = fopen(inputFileName, "rb");
    if(ifp == NULL){
        printf("ERROR: invalid input file\r\n");
        exit(-1);//Cannot continue
    }

    FILE *ofp = fopen(outputFileName, "wb");
    if(ofp == NULL){
        printf("ERROR: unable to write output to \"%s\"\r\n", outputFileName);
        fclose(ofp);
        exit(-1);//Cannot continue
    }

    //Find size of binary file
    //FIXME: This code supports files up to 2GB in size.
    //FIXME: SEEK_END need not necessarily be supported.
    fseek(ifp, 0, SEEK_END);
    fileSize = ftell(ifp);
    rewind(ifp);
    //Pad with zeroes if necessary.
    padding = 0;
    if(fileSize % BLOCK_SIZE != 0){
        padding = BLOCK_SIZE - (fileSize % BLOCK_SIZE);
    }

    //Allocate array to hold file data plus one additional block which will hold
    //  padding information.
    data = (unsigned char*)malloc((fileSize + padding + BLOCK_SIZE) * sizeof(unsigned char));
    //Fill out the last two blocks of data. The last block contains number of
    //  padding bytes, whereas the previous one might be padded.
    memset(&data[fileSize + padding - BLOCK_SIZE], padding, 2*BLOCK_SIZE);

    //Read file into array
    fread(&data[0], fileSize, 1, ifp);

    nextByte = 0;
    threadInfo = (threadInfo_t) { .data = data,
                                  .keyArray = &keyArray[0],
                                  .length = fileSize + padding + BLOCK_SIZE,
                                  .nextByte = &nextByte,
                                  .mutex = &mutex
                                };
    printf("Encrypting with %d threads\r\n", NUM_CORES);
    //Create threads
    for(i = 0; i < NUM_CORES; i++){
        pthread_create(&threads[i], NULL, &encryptFile_thread, &threadInfo);
    }
    //Join threads
    for(i = 0; i < NUM_CORES; i++){
        pthread_join(threads[i], NULL);
    }

    fwrite(&data[0], fileSize + padding + BLOCK_SIZE, 1, ofp);

    fclose(ifp);
    fclose(ofp);
}

void* encryptFile_thread(void* p){
    threadInfo_t threadInfo = *((threadInfo_t*)p);
    unsigned char* data = threadInfo.data;
    const long length = threadInfo.length;
    long *nextByte = threadInfo.nextByte;
    long localNextByte;
    pthread_mutex_t *mutex = threadInfo.mutex;
    unsigned char localBlock[BLOCK_SIZE];
    unsigned char localKey[KEY_ARRAY_SIZE];
    memcpy(&localKey[0], threadInfo.keyArray, KEY_ARRAY_SIZE);

    pthread_mutex_lock(mutex);
    localNextByte = *nextByte;
    *nextByte += BLOCK_SIZE;
    pthread_mutex_unlock(mutex);

    while(localNextByte < length){
        memcpy(&localBlock[0], &data[localNextByte], BLOCK_SIZE);
        encryptBlock(&localBlock[0], &localKey[0]);
        memcpy(&data[localNextByte], &localBlock[0], BLOCK_SIZE);

        pthread_mutex_lock(mutex);
        localNextByte = *nextByte;
        *nextByte += BLOCK_SIZE;
        pthread_mutex_unlock(mutex);
    }
    return 0;
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

void decryptFile(char* inputFileName, char* outputFileName, char* key){
    unsigned char keyArray[KEY_ARRAY_SIZE];
    unsigned char data[BLOCK_SIZE];
    unsigned char bytesRead;
    int i;
    unsigned char paddingBytes;
    parseKey(key, keyArray);
    expand(&keyArray[0]);

    FILE *ifp = fopen(inputFileName, "rb");
    if(ifp == NULL){
        printf("ERROR: invalid input file\r\n");
        exit(-1);//Cannot continue
    }

    FILE *ofp = fopen(outputFileName, "wb");
    if(ofp == NULL){
        printf("ERROR: unable to write output to \"%s\"\r\n", outputFileName);
        fclose(ofp);
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
