CC=gcc
CFLAGS=-I../src -I../build/include
LDFLAGS=-L../build/lib -loqs -loqs-internal -lcrypto -lssl

 .PHONY: all clean test_sig
all: test_sig

test_sig: test_sig.c
	$(CC) $(CFLAGS) test_sig.c $(LDFLAGS) -o test_sig

clean:
	rm -f test_sig
