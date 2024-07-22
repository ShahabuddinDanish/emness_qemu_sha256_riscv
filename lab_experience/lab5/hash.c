#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <string.h>

#define SHA256_IOC_MAGIC 'k'
#define SHA256_IOC_GET_ID _IOR(SHA256_IOC_MAGIC, 0, int)
#define SHA256_IOC_GET_STATUS _IOR(SHA256_IOC_MAGIC, 1, int)
#define SHA256_IOC_START_HASH _IOW(SHA256_IOC_MAGIC, 2, int)
#define SHA256_IOC_RESET _IOW(SHA256_IOC_MAGIC, 3, int)

#define inputBufferSize     1024
#define outputBufferSize    32

int main() {
    
    int fd;
    uint32_t id;
    char input[inputBufferSize];
    uint8_t output[outputBufferSize];
    int read_bytes;

    // Open the SHA256 device
    fd = open("/dev/sha2560", O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device");
        return -1;
    }

    // Read the ID register
    if (ioctl(fd, SHA256_IOC_GET_ID, &id) == -1) {
        perror("Failed to get device ID");
        close(fd);
        return -1;
    }
    printf("Device ID: %x\n", id);

    // Get input from the user
    printf("Enter a string to hash: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;    // Remove newline character if present

    // Write the input to the device
    if (write(fd, input, strlen(input)) < 0) {
        perror("Failed to write to the device");
        close(fd);
        return -1;
    }

    // Initiate the hashing process
    if (ioctl(fd, SHA256_IOC_START_HASH, NULL) == -1) {
        perror("Failed to start hashing process");
        close(fd);
        return -1;
    }

    // Read the hash output from the device
    read_bytes = read(fd, output, outputBufferSize);
    if (read_bytes < 0) {
        perror("Failed to read from the device");
        close(fd);
        return -1;
    }

    // Print the hash output
    printf("The Final SHA256 Hash: ");
    for (int i = 0; i < outputBufferSize; ++i) {
        printf("%02x", output[i]);
    }
    printf("\n");

    // Close the device
    close(fd);
    return 0;
}
