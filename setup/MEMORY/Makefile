CC = gcc
CFLAGS = -O0 -Wall -Wextra
TARGETS = Malloc Memory_Rate_Generator

all: $(TARGETS)

Malloc: Malloc.c
	$(CC) $(CFLAGS) -o $@ $<

Memory_Rate_Generator: Memory_Rate_Generator.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
