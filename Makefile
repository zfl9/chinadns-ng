CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -O3
SRCS = chinadns.c dnsutils.c maputils.c netutils.c
OBJS = $(SRCS:.c=.o)
MAIN = chinadns-ng

.PHONY: all clean

all: $(MAIN)

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) -s $(OBJS) -o $(MAIN)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) *.o $(MAIN)
