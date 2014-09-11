
KEYS  = serv.privkey.pem serv.cacert.pem serv.pubkey.pem
KEYS += client.privkey.pem client.cacert.pem client.pubkey.pem
EXE  = serv client

CFLAGS  = -Wextra -Wall -g -Wpedantic -Werror
CFLAGS += $(shell pkg-config libssl --cflags)

LDFLAGS = $(shell pkg-config libssl --libs) -lpthread

DEP_FILE = .$(shell pwd | sed 's|/||g').depend

all: $(DEP_FILE) $(KEYS) $(EXE)

serv: serv.o ssl.o
	$(CC) $(LDFLAGS) $^ -o $@

client: client.o ssl.o
	$(CC) $(LDFLAGS) $^ -o $@

%.privkey.pem:
	openssl genrsa -out $@ 2048

%.cacert.pem: %.privkey.pem
	openssl req -new -x509 -key $^ -out $@ -days 1095

%.pubkey.pem: %.cacert.pem
	openssl x509 -pubkey -noout -in $^ > $@

clean:
	rm -f *~ $(EXE) *.o

.PHONY: dep
$(DEP_FILE) dep: Makefile
	$(CC) $(CFLAGS) -MM -MG *.c > $(DEP_FILE)

ifeq ($(DEP_FILE),$(wildcard $(DEP_FILE)))
include $(DEP_FILE)
endif
