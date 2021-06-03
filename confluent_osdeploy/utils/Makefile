CC := gcc
CFLAGS := -Os
TARGETS := copernicus autocons start_root

all: $(TARGETS) clortho

clortho: clortho.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypt
	strip -s $@

$(TARGETS): % : %.c
	$(CC) $(CFLAGS) -o $@ $^
	strip -s $@

clean:
	rm $(TARGETS) clortho
