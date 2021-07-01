vtbufferd: vtbufferd.c tmt.c
	gcc -O3 --std=gnu11 -o vtbufferd vtbufferd.c tmt.c

clean:
	rm -f vtbufferd

install:
	mkdir -p $(DESTDIR)/opt/confluent/bin
	$(INSTALL) -s vtbufferd $(DESTDIR)/opt/confluent/bin

