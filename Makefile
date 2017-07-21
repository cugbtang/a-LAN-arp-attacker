CC = gcc
CFLAGS = -Wall -g -c
INCLUDES =
LIBS = -lpcap -lnet -lpthread

SRC = $(wildcard *.c)
OBJS = $(SRC:.c=.o)

TARGET = arp_attacker

%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

.PHONY: clean
clean:
	rm -rf $(OBJS)
