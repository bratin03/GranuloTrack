CC = gcc
CFLAGS = -O0 -Wall -Wextra -pthread
TARGETS = WorkLoad_1 WorkLoad_2 CPU_Load_Generator

all: $(TARGETS)

WorkLoad_1: WorkLoad_1.c
	$(CC) $(CFLAGS) -o $@ $<

WorkLoad_2: WorkLoad_2.c
	$(CC) $(CFLAGS) -o $@ $<

CPU_Load_Generator: CPU_Load_Generator.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
