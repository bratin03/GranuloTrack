obj-m += kmalloc_lkm.o

# Kernel module build
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	$(CC) -o Test Test.c   # Compile test.c using GCC

# Clean both kernel module and test binary
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(RM) Test
