
EXE = z gun
CC = gcc -Wall -pipe -g -Werror

LDFLAGS = -lz

all: $(EXE)

z: main.o
	$(CC) $(LDFLAGS) $^ -o $@

gun: gun.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(EXE) *.o *~
