#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define SHA256_IOC_MAGIC 'k'
#define SHA256_IOC_GET_ID _IOR(SHA256_IOC_MAGIC, 0, int)

int main() {
    int fd = open("/dev/sha2560", O_RDWR);  // Open the device
    uint32_t id;

    if (fd < 0) {
        perror("Failed to open device");
        return -1;
    }

    if (ioctl(fd, SHA256_IOC_GET_ID, &id) == -1) {
        perror("Failed to get device ID");
        close(fd);
        return -1;
    }

    printf("Device ID: %x\n", id);
    close(fd);
    return 0;
}
