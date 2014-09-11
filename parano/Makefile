
CC = gcc -Wall -Wextra -pipe -g -Werror
EXE = time child mother poll pause thread_cancel wait_status popen thread_join

MOTHER = mother
CHILD = child

all: $(EXE)

redirect.o: redirect.c
	$(CC) $(CFLAGS) -DMOTHER_NAME=\"$(MOTHER)\" -DCHILD_NAME=\"$(CHILD)\" -c $< -o $@

$(CHILD): redirect.o
	$(CC) $(LDFLAGS) $^ -o $@

$(MOTHER): redirect.o
	$(CC) $(LDFLAGS) $^ -o $@

thread_cancel: thread_cancel.o
	$(CC) $(LDFLAGS) -pthread $^ -o $@

thread_join: thread_join.o
	$(CC) $(LDFLAGS) -pthread $^ -o $@

clean:
	rm -f *~ *.o $(EXE)
