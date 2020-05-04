CC := gcc
CFLAGS := -Os
TARGETS := copernicus autocons

all: $(TARGETS) clortho

clortho: clortho.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypt
	strip -s $@

$(TARGETS): % : %.c
	$(CC) $(CFLAGS) -o $@ $^
	strip -s $@
