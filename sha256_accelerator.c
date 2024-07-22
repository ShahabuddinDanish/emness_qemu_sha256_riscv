/**
 ****************************************************************************************
 * @file    sha256_accelerator.c
 * @author  Areeb Ahmed, Shahabuddin Danish
 * @brief   This file implements the custom SHA256 Accelerator Core in QEMU.
 **************************************************************************************** 
 */

/* Includes -------------------------------------------------------------------------- */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/hw.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "hw/misc/sha256_accelerator.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

#define TYPE_SHA256_DEVICE "sha256_device"
typedef struct SHA256DeviceState SHA256DeviceState;
DECLARE_INSTANCE_CHECKER(SHA256DeviceState, SHA256_DEVICE, TYPE_SHA256_DEVICE)

/* Device Register Mapping ----------------------------------------------------------- */

#define ID_REG      0x0000          // Base register to hold device identification information
#define INIT_REG    0x0004			
#define CTRL_REG    0x0008          // Control operation of the core, such as starting computation or resetting the core
#define STATUS_REG  0x000C          // Status information regarding the core, such as whether it is idle or busy 
#define INPUT_REG   0x0010          // Store the input string from the user to be encrypted (1KB input buffer)
#define OUTPUT_REG  0x0410          // Retrieve the output string containing the final SHA256 digest from the core

/* Device Macros Definitions --------------------------------------------------------- */

#define deviceEN            0x00000001      // Bitmask to enable the core
#define deviceRST			0x00000000		// Bitmask to reset the core
#define DEVICE_ID			0xFEEDCAFE     	// Harcoded ID information for the accelerator core
#define inputBufferSize     1024            // 1024 bytes for input size
#define outputBufferSize    32              // 32 byte (256 bits) buffer for final digest 
#define CHUNK_SIZE          64              // Size of each chunk in words (512 bits)

#define RIGHT_ROTATE(value, n) (((value) >> (n)) | ((value) << (32 - (n))))

/* SHA256 Algorithm (Accelerator Implementation) ------------------------------------- */

uint8_t digest[outputBufferSize];			// Array to store final digest (8 hash values * 4 bytes/hash = 32 bytes digest)

int perform_sha256_hashing(char *inputStr) {
    
    /* Determine the size of the input string */
    size_t inStrSize = strlen(inputStr);

	unsigned char* messageBlock;
	int numBlocks;			
	int messageBlockSize;
	int numChunks;
	unsigned char** chunks;
	int chunkIndex = 0;
	uint32_t w[64];					// Message schedule array

	/* Initilizaing hash values */
    uint32_t hashVal[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };
    
	/* Calculate the required size for the message block as a multiple of 512 */
    messageBlockSize = ((inStrSize * 8) + 72 + 511);	// Adding 72 for the last reserved bits, 511 to round up to nearest multiple of 512
	numBlocks = messageBlockSize / 512;					// Calculate number of 512 bit blocks
	messageBlockSize = (numBlocks * 512) / 8;

    messageBlock = (unsigned char*)malloc(messageBlockSize * sizeof(unsigned char));
    if (messageBlock == NULL) {
        printf("Memory allocation failed for message block.\n");
        return 1;
    }

	memset(messageBlock, 0, messageBlockSize * sizeof(unsigned char));			// Initialize message block with zeros
	encodeMessageBlock(inputStr, messageBlock, inStrSize, messageBlockSize);

	/* Create a chunks array to the 512-bit chunks of the message block */
	numChunks = (messageBlockSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
	chunks = (unsigned char**)malloc(numChunks * sizeof(unsigned char*));
	if(chunks == NULL) {
		printf("Memory allocation failed for chunks.\n");
		free(messageBlock);
		return 1;
	}

	/* Initialize each chunk in the chunks array */
	for (int i = 0; i < numChunks; ++i) {
		chunks[i] = (unsigned char*)malloc(CHUNK_SIZE * sizeof(unsigned char));
		if (chunks[i] == NULL) {
			printf("Memory allocation failed for chunk %d.\n", i);
			// Free previously allocated memory
			for (int j = 0; j < i; ++j) {
				free(chunks[j]);
			}
			free(chunks);
			free(messageBlock);
			return 1;
		}
		memset(chunks[i], 0, CHUNK_SIZE * sizeof(unsigned char));
	}

	/* Divide the message block into 512-bit chunks and store them in the chunks array */
	for (int i = 0; i < messageBlockSize; ++i) {
		chunks[chunkIndex][i % CHUNK_SIZE] = messageBlock[i];
		if ((i + 1) % CHUNK_SIZE == 0) {
			chunkIndex++;
		}
	}

	/* Create the message schedule performing compression for each chunk */
	for(chunkIndex = 0; chunkIndex < numChunks; ++chunkIndex){
		messageSchedule(chunkIndex, chunks, numChunks, w);	// Generate message schedule for current chunk
		compression(hashVal, w); 							// Perform compression using the current chunk
	}

	/* Append the hash values to the digest array */
	for (int i = 0; i < 8; ++i) {
		digest[i * 4] = (hashVal[i] >> 24) & 0xFF;
		digest[i * 4 + 1] = (hashVal[i] >> 16) & 0xFF;
		digest[i * 4 + 2] = (hashVal[i] >> 8) & 0xFF;
		digest[i * 4 + 3] = hashVal[i] & 0xFF;
    }

	/* Free dynamically allocated memory */
	free(messageBlock);
	for (int i = 0; i < numChunks; ++i) {
		free(chunks[i]);
	}
	free(chunks);

	return 0;

}

void encodeMessageBlock(char* inStr, unsigned char messageBlock[], const int inSize, const int messageBlockSize) {
	
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

void compression(uint32_t hashVal[], uint32_t w[]) {

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

	// Now update the hash values

	hashVal[0] += a;
	hashVal[1] += b;
	hashVal[2] += c;
	hashVal[3] += d;
	hashVal[4] += e;
	hashVal[5] += f;
	hashVal[6] += g;
	hashVal[7] += h;

}

/* Device Modelling with QOM ------------------- ------------------------------------- */

struct SHA256DeviceState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;    						// Memory region for device I/O
    char inputBuffer[inputBufferSize];   	    // Buffer to store input data
    uint8_t outputBuffer[outputBufferSize]; 	// Buffer to store output SHA256 hash
    uint32_t control;      						// Control register to start/stop and manage the device
    uint32_t status;       						// Status register to indicate device state (e.g., busy, ready)
};

static uint64_t sha_device_read(void *opaque, hwaddr addr, unsigned int size)
{
    SHA256DeviceState *s = (SHA256DeviceState *)opaque;
	uint64_t data = 0;

    // Handle specific device registers
    switch (addr) {
        case ID_REG: 			// Device ID Register
			return DEVICE_ID;	// Return the predefined device ID

        case CTRL_REG: 			// Control Register
			return s->control;	// Return the current value of the control register

        case STATUS_REG: 		// Status Register
			return s->status; 	// Return the current value of the status register
    }

	// Handle memory-mapped I/O for input and output buffers
    
    if (addr >= INPUT_REG && addr < INPUT_REG + inputBufferSize) {
        
		// Calculate the exact byte offset within the input buffer
        int offset = addr - INPUT_REG;
        
		// For Debugging
		// printf("sha_device_read: Reading from input register at address: 0x%08x\n", (int)addr);
        
        // Ensure the offset is within bounds
        if (offset + size > inputBufferSize) {
            printf("sha_device_read: Read out of bounds\n");
            return 0xDEADBEEF; // Return error value for out-of-bounds read
        } else {
			switch (size) {
				case 1:
					data = s->inputBuffer[offset];
					break;
				case 2:
					data = s->inputBuffer[offset] | (s->inputBuffer[offset + 1] << 8);
					break;
				case 4:
					data = s->inputBuffer[offset] | (s->inputBuffer[offset + 1] << 8) |
						(s->inputBuffer[offset + 2] << 16) | (s->inputBuffer[offset + 3] << 24);
					break;
				default:
					printf("sha_device_read: Invalid read size %u at address 0x%08x\n", size, (int)addr);
					return 0xDEADBEEF;
			}
			return data;
		}

    } else if (addr >= OUTPUT_REG && addr < OUTPUT_REG + outputBufferSize) {
        
		// Calculate the exact byte offset within the output buffer
        int offset = addr - OUTPUT_REG;
        
		// For Debugging
		// printf("sha_device_read: Reading from output register at address: 0x%08x\n", (int)addr);

        // Ensure the offset is within bounds
        if (offset + size > outputBufferSize) {
            printf("sha_device_read: Read out of bounds\n");
            return 0xDEADBEEF; // Return error value for out-of-bounds read
        } else {
			switch (size) {
				case 1:
					data = ((uint8_t*)s->outputBuffer)[offset];
					break;
				case 2:
					data = ((uint8_t*)s->outputBuffer)[offset] | (((uint8_t*)s->outputBuffer)[offset + 1] << 8);
					break;
				case 4:
					data = ((uint8_t*)s->outputBuffer)[offset] | (((uint8_t*)s->outputBuffer)[offset + 1] << 8) |
						(((uint8_t*)s->outputBuffer)[offset + 2] << 16) | (((uint8_t*)s->outputBuffer)[offset + 3] << 24);
					break;
				default:
					printf("sha_device_read: Invalid read size %u at address 0x%08x\n", size, (int)addr);
					return 0xDEADBEEF;
			}
			return data;
		}

    } else {
        printf("sha_device_read: Invalid read address 0x%08x\n", (int)addr);
        qemu_log_mask(LOG_GUEST_ERROR, "sha_device_read: Invalid read address 0x%08x\n", (int)addr);
        return 0xDEADBEEF; // Return error value for undefined addresses
    }

    return 0;
}

static void sha_device_write(void *opaque, hwaddr addr, uint64_t data, unsigned int size)
{
    SHA256DeviceState *s = (SHA256DeviceState *)opaque;

    // Handling specific control registers
    
	switch (addr) {
        case CTRL_REG: 				// Control Register
			s->control = data; 								// Update the control register
			
			if (data == deviceEN) { 						// Check if the enable bit is set to start hashing
				
				perform_sha256_hashing(s->inputBuffer);
				memcpy(s->outputBuffer, digest, outputBufferSize * sizeof(uint8_t)); 	// Copy 256 bit hash (32 elements * 1 byte per element)
				s->status = 1; 		// Update the status register to indicate completion
			
				/* Debugging Print Statements */
				/*
				// Input Buffer Checking
				printf("sha_device_write: Data in input register: ");
				for (int i = 0; i < inputBufferSize; i++) {
					printf("%02X", (unsigned char)s->inputBuffer[i]);
				}
				printf("\n");

				// Temporary Buffer Checking
				printf("sha_device_write: Writing output digest.\n");
				printf("SHA256 Digest: ");
				for (int i = 0; i < 32; ++i) {
					printf("%02X", digest[i]);
				}
				printf("\n");

				// Output Buffer Checking
				printf("sha_device_write: Data in output register: ");
				for (int i = 0; i < outputBufferSize; ++i) {
					printf("%02X", s->outputBuffer[i]);
				}
				printf("\n");
			*/			
			} else if (data == deviceRST) {

				printf("sha_device_write: Resetting SHA256 Accelerator Core.");
			 	s->status = 0; 														// Reset the status register
				memset(s->inputBuffer, 0, inputBufferSize); 						// Clear the input buffer
    			memset(s->outputBuffer, 0, outputBufferSize * sizeof(uint8_t)); 	// Clear the output buffer
 
			}
			return;

        default:
            break;
    }

    // Handle writes to the input buffer
    if (addr >= INPUT_REG && addr < INPUT_REG + inputBufferSize) {
        // Calculate the exact byte offset within the input buffer
        int offset = addr - INPUT_REG;
		s->inputBuffer[offset] = data;
		
		// For Debugging
		// printf("sha_device_write: Writing to input register: %llu at address: 0x%08x of size: %u\n", (unsigned long long)data, (int)addr, size);
		
		return; // Exit after handling input buffer writes
	} else {
		// Log an error if no valid address was matched
		qemu_log_mask(LOG_GUEST_ERROR, "sha_device_write: Invalid write address 0x%08x\n", (int)addr);
	}

}

static const MemoryRegionOps sha_device_ops = {
	.read = sha_device_read,
    .write = sha_device_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void sha_instance_init(Object *obj)
{
    SHA256DeviceState *s = SHA256_DEVICE(obj);

	/* allocate memory map region */ 
    memory_region_init_io(&s->iomem, obj, &sha_device_ops, s, "sha256_device", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);

    // Initialize the state of the device
    s->status = 0; 									// Set initial status as 0 (e.g., device ready or idle)
    s->control = 0; 								// Ensure the control register is set to 0 initially
    memset(s->inputBuffer, 0, inputBufferSize); 	// Clear the input buffer
    memset(s->outputBuffer, 0, outputBufferSize * sizeof(uint8_t)); 	// Clear the output buffer
}

static TypeInfo sha256_device_info = {
    .name = TYPE_SHA256_DEVICE,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(SHA256DeviceState),
    .instance_init = sha_instance_init,
};

static void sha256_device_register_types(void)
{
    type_register_static(&sha256_device_info);
}

type_init(sha256_device_register_types)