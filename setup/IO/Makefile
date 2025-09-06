CC = gcc
CFLAGS = -O0 -Wall -Wextra
TARGETS = Read Write

all: $(TARGETS)

Read: Read.c
	$(CC) $(CFLAGS) -o $@ $<

Write: Write.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
