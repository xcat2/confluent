CC := gcc
CFLAGS := -Os
TARGETS := copernicus autocons start_root

all: $(TARGETS) clortho urlmount

urlmount: urlmount.c
	$(CC) $(CFLAGS) -o $@ $^  -D_FILE_OFFSET_BITS=64  -lcurl -lm -lfuse -lpthread
	strip -s $@

clortho: clortho.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypt
	strip -s $@

$(TARGETS): % : %.c
	$(CC) $(CFLAGS) -o $@ $^
	strip -s $@

clean:
	rm $(TARGETS) clortho
