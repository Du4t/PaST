CC = gcc
CFLAGS = -Wall -fPIC -g -O0  
APP = main
FORKSRVPATH = ../../libforksrv

all: $(APP)

$(APP): main.c  
	$(CC) $(CFLAGS) -o $(APP) -static -I$(FORKSRVPATH) -L$(FORKSRVPATH) -lforksrv main.c $(FORKSRVPATH)/libforksrv.a
 
trace: $(APP)
	sudo CS_DEFER_FORKSRV=1 ../../cs-trace --decoding=edge -- ./$(APP)

fuzz: $(APP)
	sudo CS_DEFER_FORKSRV=1 ../../../../afl-fuzz -A -i in -o out -- ./$(APP)
test: $(APP) trace clean

clean:
	rm -f $(APP) *.o cstrace.bin decoderargs.txt

.PHONY: all trace fuzz test clean