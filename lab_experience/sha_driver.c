/**
 ****************************************************************************************
 * @file    sha_driver.c
 * @author  Shahabuddin Danish, Areeb Ahmed
 * @brief   This file implements the LKM for our custom SHA256 Accelerator Core in QEMU.
*/

/* Includes -------------------------------------------------------------------------- */

#include <linux/module.h>           // Core header for loading LKMs into the kernel
#include <linux/init.h>             // Macros used to mark up functions e.g. __init __exit
#include <linux/kernel.h>           // Contains types, macros, functions for the kernel
#include <linux/fs.h>               // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function
#include <linux/of.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/device.h>

/* Kernel Module Macro Definitions --------------------------------------------------- */

#define DEVICE_NAME "sha256_accelerator"    // The device name as written in the QEMU machine device tree 
#define CLASS_NAME  "sha256_accel"          // The device class name, the device will appear at /dev/sha256_accel
#define DRIVER_NAME "sha256_foo"            // LKM name 

#define SHA256_IOC_MAGIC 'k'
#define SHA256_IOC_GET_ID _IOR(SHA256_IOC_MAGIC, 0, int)
#define SHA256_IOC_GET_STATUS _IOR(SHA256_IOC_MAGIC, 1, int)
#define SHA256_IOC_START_HASH _IOW(SHA256_IOC_MAGIC, 2, int)
#define SHA256_IOC_RESET _IOW(SHA256_IOC_MAGIC, 3, int)

/* Device Macros Definitions --------------------------------------------------------- */

#define deviceEN            0x00000001
#define inputBufferSize     1024
#define outputBufferSize    32

/* Device Register Map --------------------------------------------------------------- */

#define ID_REG      0x0000
#define CTRL_REG    0x0008
#define STATUS_REG  0x000C 
#define INPUT_REG   0x0010
#define OUTPUT_REG  0x0410

/* Driver Meta Information ----------------------------------------------------------- */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SHAHABUDDIN DANISH, AREEB AHMED");
MODULE_DESCRIPTION("Custom SHA256 Accelerator Core LKM");
MODULE_VERSION("1.1");

/* Function Prototypes --------------------------------------------------------------- */

static int sha256_open(struct inode *inode, struct file *file);
static int sha256_release(struct inode *inode, struct file *file);
static ssize_t sha256_read(struct file *filep, char __user *buf, size_t count, loff_t *ppos);
static ssize_t sha256_write(struct file *filep, const char __user *buf, size_t count, loff_t *ppos);
static long sha256_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);

static int major = 0;                       // dynamically allocated
static struct cdev sha256_cdev;
static struct class *sha256_class = NULL;

struct sha256_dev {
    void __iomem *regs;
    struct device *dev;
};

static struct sha256_dev sha256_device;

static const struct file_operations sha256_fops = {
    .owner = THIS_MODULE,
    .open = sha256_open,
    .release = sha256_release,
    .read = sha256_read,
    .write = sha256_write,
    .unlocked_ioctl = sha256_ioctl,
    .compat_ioctl = sha256_ioctl
};

static int sha256_open(struct inode *inode, struct file *file) {
    
    file->private_data = &sha256_device;
    printk(KERN_INFO "SHA256: Device file opened.\n");
    return 0;
}

static int sha256_release(struct inode *inode, struct file *file) {
    
    // Perform clean-up tasks, such as freeing allocated memory
    // or shutting down hardware if no longer needed.

    printk(KERN_INFO "SHA256: Device file closed.\n");
    return 0;
}

/**
 * @brief This function reads the final SHA256 digest from the hardware device's output 
 * register and transfers it to a userspace buffer. It allows a single read operation 
 * per open instance which is suited for our device where input data must be explicitly 
 * refreshed or reacquired for every consecutive computation.
 * 
 * @param filep Pointer to file object set during open call.
 * @param buf Pointer to the kernel buffer where this function writes the read data.
 * @param count Not used here.
 * @param ppos Position pointer for the output register read offset.
 * 
 * @return returns number of bytes read or an error code.
*/

static ssize_t sha256_read(struct file *filep, char __user *buf, size_t count, loff_t *ppos) {
    
    struct sha256_dev *dev = filep->private_data;
    uint8_t output_buf;                 // Single byte kernel buffer for output digest
    
    // Reset the position pointer to zero to start reading from the beginning
    *ppos = 0;

    // Ensure the read request is within the bounds of the output buffer
    if (count > outputBufferSize) {
        count = outputBufferSize;
    }

    // Read each byte individually
    for (size_t i = 0; i < count; i++) {
        output_buf = ioread8(dev->regs + OUTPUT_REG + *ppos + i);

        // Debug: Print the byte being read
        // printk(KERN_INFO "SHA256 Driver: Reading from output register: 0x%02x at virtual address: 0x%08llx\n", output_buf, (unsigned long long)(dev->regs + OUTPUT_REG + *ppos + i));

        // Copy the byte to the userspace buffer
        if (copy_to_user(buf + i, &output_buf, 1)) {
            return -EFAULT;  // Return error if copy to userspace fails
        }
    }

    /* Update the position pointer */
    *ppos += count;

    /* Return the number of bytes read, always 32 */
    return count;

}

/**
 * @brief Writes data from userspace to the SHA256 device's input register for hashing. It
 * also initiates the hashing process by writing to the control register. This automatic
 * computation approach is chosen to simplify userspace logic and because there is no extra
 * device configuration to be performed after writing the input buffer. 
 * 
 * @param filep Pointer to file object set during open call.
 * @param buf Pointer to the user buffer from which data is written.
 * @param count The number of bytes to write.
 * @param ppos Position pointer, not used for writing in this driver.
 * 
 * @return returns number of bytes written or an error code.
 */

static ssize_t sha256_write(struct file *filep, const char __user *buf, size_t count, loff_t *ppos) {
    
    struct sha256_dev *dev = filep->private_data;
    char input_buf;            // Single byte kernel buffer for input data

    /* Check if the input size exceeds 1KB
    if (count > inputBufferSize) {
        printk(KERN_WARNING "SHA256: Input size exceeds 1KB, rejecting the input.\n");
        return -EINVAL;  // Return an error code indicating invalid argument
    }
    */

    // Check the amount of data to be written does not exceed the input buffer size
    if (count > inputBufferSize) {
        count = inputBufferSize;
    }

    // Write each byte individually
    for (size_t i = 0; i < count; i++) {
        if (copy_from_user(&input_buf, buf + i, 1)) {
            return -EFAULT;  // Return error if copy from userspace fails
        }

        // Debug: Print the byte being written
        // printk(KERN_INFO "SHA256 Driver: Writing to input register: 0x%02x at virtual address: 0x%08llx\n", input_buf, (unsigned long long)(dev->regs + INPUT_REG + *ppos + i));

        // Write the byte to the device's input register
        iowrite8(input_buf, dev->regs + INPUT_REG + *ppos + i);
    }

    // Update the position pointer
    *ppos += count;

    // Return the number of bytes written
    return count;
}

/**
 * @brief IOCTL function for SHA256 device control.
 * 
 * @param filep Pointer to file object set during open call.
 * @param cmd IOCTL command from userspace.
 * @param arg Argument for the IOCTL command.
 * 
 * @return returns 0 indicating success of the IOCTL operation or an error.
 */

static long sha256_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {

    struct sha256_dev *dev = filep->private_data;
    int status;

    switch (cmd) {
        case SHA256_IOC_GET_ID:
        // Read the device ID register
            uint32_t id = ioread32(dev->regs + ID_REG);
            if (copy_to_user((uint32_t __user *)arg, &id, sizeof(id)))
                return -EFAULT;
            break;

        case SHA256_IOC_GET_STATUS:
            // Read the device status
            status = ioread32(dev->regs + STATUS_REG);

            // Copy the status back to user space
            if (copy_to_user((int __user *)arg, &status, sizeof(status)))
                return -EFAULT;
            break;

        case SHA256_IOC_START_HASH:
            // Write EN to the control register to initiate the hashing process
            iowrite32(deviceEN, dev->regs + CTRL_REG);
            printk(KERN_INFO "SHA256: Hashing process started.\n");
            break;

        case SHA256_IOC_RESET:
            // Reset the device by writing reset value to the control register
            iowrite32(0, dev->regs + CTRL_REG);         // change this 0 to a fixed macro to make it generic (for future)
            printk(KERN_INFO "SHA256: Device reset\n");
            break;

        default:
            // Return error for unknown command
            return -ENOTTY;     // "Not a typewriter" - invalid ioctl command
    }

    return 0; // Success
}

/**
 * @brief Probes for the SHA256 device at module initialization.
 * This function is called by the Linux kernel when the platform driver is registered
 * and a matching device is found in the device tree or when a device that matches
 * the compatible string defined in the driver's of_match_table is initialized.
 * 
 * @param pdev Pointer to the platform_device structure, representing the SHA256 device
 * identified by the platform bus.
 *
 * @return Returns 0 on success, negative error codes on failure.
*/

static int sha256_probe(struct platform_device *pdev) {

    printk(KERN_INFO "SHA256: Probe function called.\n");

    struct resource *res;
    struct device *dev = &pdev->dev;
    int rc;

    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    if (!res) {
        dev_err(dev, "No memory resource\n");
        return -ENODEV;
    }

    sha256_device.regs = devm_ioremap_resource(dev, res);
    if (IS_ERR(sha256_device.regs)) {
        dev_err(dev, "Cannot map registers\n");
        return PTR_ERR(sha256_device.regs);
    }

    sha256_device.dev = dev;

    // Register the device - create cdev entry
    cdev_init(&sha256_cdev, &sha256_fops);
    sha256_cdev.owner = THIS_MODULE;
    rc = cdev_add(&sha256_cdev, MKDEV(major, 0), 1);
    if (rc) {
        dev_err(dev, "Failed to add cdev\n");
        return rc;
    }

    // Create class entry
    struct device *result = device_create(sha256_class, dev, MKDEV(major, 0), NULL, "sha256%d", 0);
    if (IS_ERR(result)) {
        printk(KERN_ERR "Failed to create device: %ld\n", PTR_ERR(result));
    } else {
        printk(KERN_INFO "SHA256 Device created successfully\n");
    }

    dev_info(dev, "SHA256 device initialized\n");
    return 0;
}

static int sha256_remove(struct platform_device *pdev) {
    device_destroy(sha256_class, MKDEV(major, 0));
    cdev_del(&sha256_cdev);
    return 0;
}

/** Device Tree: If you’re working on an embedded system or using QEMU, ensure your device
 * is properly described in the device tree. The device tree node should match the compatible
 * string specified in your driver.
*/

static const struct of_device_id sha256_of_match[] = {
    { .compatible = DEVICE_NAME },
    {},
};
MODULE_DEVICE_TABLE(of, sha256_of_match);

static struct platform_driver sha256_driver = {
    .driver = {
        .name = DRIVER_NAME,
        .owner = THIS_MODULE,
        .of_match_table = sha256_of_match,
    },
    .probe = sha256_probe,
    .remove = sha256_remove,
};

static int __init sha256_init(void) {
    
    printk(KERN_INFO "SHA256: Initializing the driver\n");

    dev_t dev_id;
    int ret;

    // Allocate a major number dynamically
    ret = alloc_chrdev_region(&dev_id, 0, 1, "sha256");
    if (ret < 0) {
        printk(KERN_ERR "SHA256: Unable to allocate major number\n");
        return ret;
    }
    
    major = MAJOR(dev_id);

    // Create a device class
    sha256_class = class_create(CLASS_NAME);
    
    // Change the above line to this one when compiling for x86 due to the kernel version discrepancy
    // sha256_class = class_create(THIS_MODULE, CLASS_NAME);

    if (IS_ERR(sha256_class)) {
        unregister_chrdev_region(MKDEV(major, 0), 1);
        printk(KERN_ERR "SHA256: failed to register device class\n");
        return PTR_ERR(sha256_class);
    }

    // Register the platform driver
    ret = platform_driver_register(&sha256_driver);
    if (ret != 0) {
        class_destroy(sha256_class);
        unregister_chrdev_region(MKDEV(major, 0), 1);
        printk(KERN_ERR "SHA256: failed to register platform driver\n");
        return ret;
    }

    printk(KERN_INFO "SHA256 driver loaded with major %d\n", major);
    return 0;
}

static void __exit sha256_exit(void) {

    printk(KERN_INFO "SHA256: Exiting the driver\n");
    platform_driver_unregister(&sha256_driver);
    class_destroy(sha256_class);
    unregister_chrdev_region(MKDEV(major, 0), 1);
    printk(KERN_INFO "SHA256: driver unregistered\n");

}

module_init(sha256_init);
module_exit(sha256_exit);