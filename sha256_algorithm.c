#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// #define INPUT_MAX_LIMIT 100
// Not needed after implementing the malloc

#define CHUNK_SIZE 64 // Size of each chunk in words (512 bits)
#define RIGHT_ROTATE(value, n) (((value) >> (n)) | ((value) << (32 - (n))))

void encodeMessageBlock();
void messageSchedule();
void compression();

int main() {

	char* inputStr = NULL;
	size_t inputSizeBuffer = 0;
	int inStrSize;
	
	unsigned char* messageBlock;
	int numBlocks;			
	int messageBlockSize;

	int numChunks;
	unsigned char** chunks;
	int chunkIndex = 0;
	uint32_t w[64];			// Create the message schedule array with 64 words

	uint32_t digest[32];	// Array to store final digest (8 hash values * 4 bytes/hash)

	// Initilizaing hash values
    const uint32_t hashVal[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

	printf("Enter string to hash: ");

	// dynamically allocate memory for the input string, resizing the buffer as needed
	getline(&inputStr, &inputSizeBuffer, stdin);

	// Remove trailing newline character, if present
	inputStr[strcspn(inputStr, "\n")] = '\0';

    // Determine the size of the input string
    inStrSize = strlen(inputStr);

    // Calculate the required size for the message block as a multiple of 512
    messageBlockSize = ((inStrSize * 8) + 72 + 511);		// Adding 72 for the last reserved bits, 511 to round up to nearest multiple of 512
	numBlocks = messageBlockSize / 512;						// Calculate number of 512 bit blocks
	messageBlockSize = (numBlocks * 512) / 8;

	/* For Debugging
	printf("The size of message block will be %d 8-bit words.\n", (messageBlockSize * sizeof(unsigned char)));
	*/

    // Dynamically allocate memory for the message block

    messageBlock = (unsigned char*)malloc(messageBlockSize * sizeof(unsigned char));
    if (messageBlock == NULL) {
        printf("Memory allocation failed for message block.\n");
        free(inputStr);
        return 1;
    }

	// Initialize message block with zeros
	memset(messageBlock, 0, messageBlockSize * sizeof(unsigned char));

	encodeMessageBlock(inputStr, messageBlock, inStrSize, messageBlockSize);

	/* Printing the array for debugging
	printf("Message Block: ");
	
	for(int i = 0; i < (messageBlockSize); ++i) {
		for(int j = 7; j >= 0; --j) {
			printf("%d", (messageBlock[i] >> j) & 1);
		}
		printf(" ");
	}
	
	printf("\n");
	*/

	// Create a chunks array to the 512-bit chunks of the message block
	numChunks = (messageBlockSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
	// For debugging
	// printf("The number of chunks is: %d\n", numChunks);
	chunks = (unsigned char**)malloc(numChunks * sizeof(unsigned char*));
	if(chunks == NULL) {
		printf("Memory allocation failed for chunks.\n");
		free(inputStr);
		free(messageBlock);
		return 1;
	}

	// Initialize each chunk in the chunks array

	for (int i = 0; i < numChunks; ++i) {
		chunks[i] = (unsigned char*)malloc(CHUNK_SIZE * sizeof(unsigned char));
		if (chunks[i] == NULL) {
			printf("Memory allocation failed for chunk %d.\n", i);
			// Free previously allocated memory
			for (int j = 0; j < i; ++j) {
				free(chunks[j]);
			}
			free(chunks);
			free(inputStr);
			free(messageBlock);
			return 1;
		}
		memset(chunks[i], 0, CHUNK_SIZE * sizeof(unsigned char));
	}

	// Divide the message block into 512-bit chunks and store them in the chunks array

	for (int i = 0; i < messageBlockSize; ++i) {
		chunks[chunkIndex][i % CHUNK_SIZE] = messageBlock[i];
		if ((i + 1) % CHUNK_SIZE == 0) {
			chunkIndex++;
		}
	}
	/* For Debugging
	// Print the chunks of the message block in binary format
	printf("Message Block Chunks:\n");
	for (int i = 0; i < numChunks; ++i) {
		printf("Chunk %d: ", i);
		for (int j = 0; j < CHUNK_SIZE; ++j) {
			for (int k = 7; k >= 0; --k) {
				printf("%d", (chunks[i][j] >> k) & 1);
			}
			printf(" ");
		}
		printf("\n");
	}
	*/

	// Create the message schedule performing compression for each chunk
	for(int chunkIndex = 0; chunkIndex < numChunks; ++chunkIndex){
		//Generate message schedule for current chunk
		messageSchedule(chunkIndex, chunks, numChunks, w);
	
		/* For Debugging
		// Print the message schedule in hexadecimal
		printf("Message Schedule:\n");
		for (int i = 0; i < 64; ++i) {
			printf("w[%2d]: 0x%08X\n", i, w[i]);
		}

		// Print the message schedule in binary 
		printf("\nMessage Schedule in Binary:\n");
		for (int i = 0; i < 64; ++i) {
			printf("w[%2d]: ", i);
			for (int j = 31; j >= 0; --j) {
				printf("%d", (w[i] >> j) & 1);
			}
			printf("\n");
		}
		*/

		// Perform compression using the current chunk
		compression(hashVal, w);
	}

	// Append the hash values to the digest array
	for (int i = 0; i < 8; ++i) {
		digest[i * 4] = (hashVal[i] >> 24) & 0xFF;
		digest[i * 4 + 1] = (hashVal[i] >> 16) & 0xFF;
		digest[i * 4 + 2] = (hashVal[i] >> 8) & 0xFF;
		digest[i * 4 + 3] = hashVal[i] & 0xFF;
    }

	// Print the final digest value
	printf("SHA256 Digest: ");
	for (int i = 0; i < 32; ++i) {
		printf("%02X", digest[i]);
	}
	printf("\n");

	// Free dynamically allocated memory
	free(inputStr);
	free(messageBlock);
	for (int i = 0; i < numChunks; ++i) {
		free(chunks[i]);
	}
	free(chunks);

	return 0;

}

void encodeMessageBlock(const char* inStr, unsigned char messageBlock[], const int inSize, const int messageBlockSize) {
	
	int index = 0;			// index of the message block array
	int binaryDigit = 0;
	int ascii = 0;

	for(int i = 0; inStr[i] != '\0'; ++i) {
		ascii = inStr[i];
		for (int j = 7; j >= 0; --j) {
			binaryDigit = (ascii >> j) & 1;
			messageBlock[index / 8] |= (binaryDigit << (7- (index % 8)));
			index++;
		}
	}

	// Append a single 1 to the end of the input in the message block
	messageBlock[index / 8] |= (1 << (7 - (index % 8)));

    // Append the input string length as a 64-bit big endian integer in binary
    uint64_t length = (uint64_t)inSize * 8; // Convert input string length to bits
    int lengthIndex = (messageBlockSize - 8); // Calculate the starting index for appending the length

    for (int i = 0; i < 8; ++i) {
        unsigned char byte = (length >> ((7 - i) * 8)) & 0xFF;
        messageBlock[lengthIndex + i] = byte;
    }
}

void messageSchedule(int chunkIndex, unsigned char** chunks, int numChunks, uint32_t w[]) {

	// Initialize the message schedule
	// Copy the first chunk of the message block into the message schedule array

	for (int i = 0; i < 16; ++i) {
		// Combine 4 bytes of the message block into a single 32-bit word
		w[i] = ((uint32_t)chunks[chunkIndex][i * 4] << 24) |
				((uint32_t)chunks[chunkIndex][i * 4 + 1] << 16) |
				((uint32_t)chunks[chunkIndex][i * 4 + 2] << 8) |
				(uint32_t)chunks[chunkIndex][i * 4 + 3];
	}

	// Calculate the remaining words in the message schedule array
	for (int i = 16; i < 64; ++i) {
		uint32_t sigma0 = RIGHT_ROTATE(w[i-15], 7) ^ RIGHT_ROTATE(w[i-15], 18) ^ (w[i-15] >> 3);
		uint32_t sigma1 = RIGHT_ROTATE(w[i-2], 17) ^ RIGHT_ROTATE(w[i-2], 19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + sigma0 + w[i-7] + sigma1;
	}
}

void compression(uint32_t hashVal[], const uint32_t w[]) {

	// Initialize the k values
	const uint32_t k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
		0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
		0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
		0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
		0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
		0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
		0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
		0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

	// Initializing the working variables

	uint32_t a = hashVal[0];
	uint32_t b = hashVal[1];
	uint32_t c = hashVal[2];
	uint32_t d = hashVal[3];
	uint32_t e = hashVal[4];
	uint32_t f = hashVal[5];
	uint32_t g = hashVal[6];
	uint32_t h = hashVal[7];

	uint32_t temp1, temp2, sumA, sumE, choice, majority;

	// Update the working variables, each round computed is the input to the next  

	for (int i = 0; i < 64; ++i) {
		sumA = RIGHT_ROTATE(e, 6) ^ RIGHT_ROTATE(e, 11) ^ RIGHT_ROTATE(e, 25);
		choice = (e & f) ^ (~e & g);
		temp1 = h + sumA + choice + k[i] + w[i];

		sumE = RIGHT_ROTATE(a, 2) ^ RIGHT_ROTATE(a, 13) ^ RIGHT_ROTATE(a, 22);
		majority = (a & b) ^ (a & c) ^ (b & c);
		temp2 = sumE + majority;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	// For Debugging
	/*
	printf("Working variable a: 0x%08X \n", a);
	printf("Working variable b: 0x%08X \n", b);
	printf("Working variable c: 0x%08X \n", c);
	printf("Working variable d: 0x%08X \n", d);
	printf("Working variable e: 0x%08X \n", e);
	printf("Working variable f: 0x%08X \n", f);
	printf("Working variable g: 0x%08X \n", g);
	printf("Working variable h: 0x%08X \n", h);
	printf("Working variable sumA: 0x%08X \n", sumA);
	printf("Working variable choice: 0x%08X \n", choice);
	printf("Working variable temp1: 0x%08X \n", temp1);
	printf("Working variable sumE: 0x%08X \n", sumE);
	printf("Working variable majority: 0x%08X \n", majority);
	printf("Working variable temp2: 0x%08X \n", temp2);
	*/

	// Now update the hash values

	hashVal[0] += a;
	hashVal[1] += b;
	hashVal[2] += c;
	hashVal[3] += d;
	hashVal[4] += e;
	hashVal[5] += f;
	hashVal[6] += g;
	hashVal[7] += h;

	// For Debugging
	/*
	printf("Working variable h0: 0x%08X \n", hashVal[0]);
	printf("Working variable h1: 0x%08X \n", hashVal[1]);
	printf("Working variable h2: 0x%08X \n", hashVal[2]);
	printf("Working variable h3: 0x%08X \n", hashVal[3]);
	printf("Working variable h4: 0x%08X \n", hashVal[4]);
	printf("Working variable h5: 0x%08X \n", hashVal[5]);
	printf("Working variable h6: 0x%08X \n", hashVal[6]);
	printf("Working variable h7: 0x%08X \n", hashVal[7]);
	*/
}