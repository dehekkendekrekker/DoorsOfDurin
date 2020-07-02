obj-m = dodlkm.o
#ccflags-y += -g -DDEBUG
dodlkm-y = src/main.o src/crypto.o src/algo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
