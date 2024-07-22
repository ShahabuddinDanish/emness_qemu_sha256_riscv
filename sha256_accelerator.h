#ifndef HW_SHA256_DEVICE_H
#define HW_SHA256_DEVICE_H

#include "qom/object.h"

/* Function prototypes */
int perform_sha256_hashing(char *inputStr);
void encodeMessageBlock(char* inStr, unsigned char messageBlock[], const int inSize, const int messageBlockSize);
void messageSchedule(int chunkIndex, unsigned char** chunks, int numChunks, uint32_t w[]);
void compression(uint32_t hashVal[], uint32_t w[]);

#endif
