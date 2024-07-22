MODULES := sha_driver.o

export ARCH := riscv
export CROSS_COMPILE := riscv64-buildroot-linux-gnu-
obj-m := $(MODULES)
KDIR := /home/shahab/OS/Linux/Project/QEMU/buildroot/output/build/linux-6.6.18

PWD:=$(CURDIR)

export
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
