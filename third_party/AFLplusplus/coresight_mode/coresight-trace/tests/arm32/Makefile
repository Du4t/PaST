CC = arm-linux-gnueabi-gcc 
CFLAGS = -Wall -fPIC -g -O0  
APP = main
FORKSRVPATH = ../../libforksrv

all: $(APP)

$(APP): main.c  
	$(CC) $(CFLAGS) -o $(APP) -static -I$(FORKSRVPATH) -L$(FORKSRVPATH) -lforksrv main.c $(FORKSRVPATH)/libforksrv32.a

trace: $(APP)
	sudo ARM32=1 CS_DEFER_FORKSRV=1 ../../cs-trace --decoding=edge -e -- ./$(APP)

fuzz: $(APP)
	sudo ARM32=1 CS_DEFER_FORKSRV=1 ../../../../afl-fuzz -A -i in -o out -- ./$(APP)
test: $(APP) trace clean

decode:
	ARM32=1 CS_DEFER_FORKSRV=1 ../../coresight-decoder/processor `cat decoderargs.txt`
clean:
	rm -f $(APP) *.o cstrace.bin decoderargs.txt device_* cpu_* kernel_dump.bin trc_pkt_lister.ppl trace.ini snapshot.ini edge_coverage_bitmap.out

.PHONY: all trace fuzz test decode clean