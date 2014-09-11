
CFLAGS  = -g -pipe -Wall -Wextra -Werror
CFLAGS += $(shell pkg-config libcurl --cflags)

LDFLAGS  = $(CFLAGS)
LDFLAGS += $(shell pkg-config libcurl --libs)

EXE = cookies cookie_interface

all: $(EXE)

cookies: main.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o *~ $(EXE) *.tab.c

%.tab.c: %.c
	$(CC) -E $^ > $@
