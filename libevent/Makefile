
topdir = /home/njagabar/git/mps

CFLAGS  = -Wextra -Wall -g
CFLAGS += $(shell pkg-config --cflags libevent_pthreads libevent_openssl)

CFLAGS += -DHAVE_CONFIG_H -DINTEGRATION -D_BSD_SOURCE -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -std=c99 -Wall -Wextra -Wall -W -Wcast-align -Wpointer-arith -Wbad-function-cast -Wmissing-prototypes -Winline -Wmissing-declarations -Wundef -Wno-unused-parameter -Wshadow -Wfloat-equal -Wno-conversion -Wconversion -Wuninitialized -fno-builtin -fdce -fdse -fno-omit-frame-pointer
CFLAGS += -I $(topdir)
CFLAGS += -I $(topdir)/include

LDFLAGS  = $(shell pkg-config --libs libevent_pthreads libevent_openssl openssl hiredis) -pthread
LDFLAGS += -Wl,-wrap,malloc -Wl,-wrap,calloc -Wl,-wrap,realloc -Wl,-wrap,free -Wl,-wrap,strdup -Wl,-wrap,__strdup -Wl,-wrap,strndup -Wl,-wrap,__strndup

VPATH = $(topdir)/libmps

EXE = server client

all: $(EXE)

server: server.o event_ssl.o logger.o util.o redis.o xmalloc.o command.o connection.o buffer.o

client: client.o event_ssl.o logger.o util.o redis.o xmalloc.o command.o connection.o buffer.o

clean:
	rm -f *.o *~ $(EXE) core core.* vgcore.*

