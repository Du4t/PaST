.PHONY: all clean

CFLAGS = -fPIC -Wall -Wextra
LDFLAGS = -shared -ldl
CROSS-COMPILER = arm-linux-gnueabi-gcc

all: libforksrv.so libforksrv.a

libforksrv.so: libforksrv.c
	-@$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@  

libforksrv.a: libforksrv.o
	ar rcs libforksrv.a libforksrv.o

libforksrv32.a: libforksrv32.o
	ar rcs libforksrv32.a libforksrv32.o

libforksrv.o: libforksrv.c
	-@$(CC) $(CFLAGS) $^ -DSTATIC -c -o $@ 

libforksrv32.o: libforksrv.c
	-@$(CROSS-COMPILER) $(CFLAGS) $^ -DSTATIC -c -o $@ 

clean:
	rm -f *.o *.a *.so

