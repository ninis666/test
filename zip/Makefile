
EXE = zip
CFLAGS = -Wextra -Wall -Werror -pipe -g

all: $(EXE)

zip: main.o
	$(CC) $(LDFLAGS) -lz $^ -o $@

clean:
	rm -f *.o *~ $(EXE)
