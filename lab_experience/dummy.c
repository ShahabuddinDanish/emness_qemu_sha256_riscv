/**
 ****************************************************************************************
 * @file    dummy.c
 * @author  Shahabuddin Danish
 * @brief   This file implements a simple LKM.
 **************************************************************************************** 
 * @attention
 * This is a dummy LKM for learning about LKM development.
*/

/* Includes -------------------------------------------------------------------------- */

#include <linux/module.h>
#include <linux/init.h>

/* Meta Information ------------------------------------------------------------------ */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("SHAHABUDDIN");
MODULE_DESCRIPTION("Dummy LKM");

/**
 * @brief This function is called when the module is loaded into the kernel.
*/
static int __init ModuleInit(void) {
    printk("Hello, kernel!\n");
    return 0;
}

/**
 * @brief This function is called when the module is removed from the kernel.
*/
static void __exit ModuleExit(void) {
    printk("Goodbye, kernel!\n");
}

module_init(ModuleInit);        // These functions tell the kernel which function of the LKM to call upon init or exit
module_exit(ModuleExit);
