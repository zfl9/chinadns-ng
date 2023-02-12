CC = gcc
# CFLAGS = -std=c99 -Wall -Wextra -Wstrict-aliasing -fstrict-aliasing -Og -ggdb3
CFLAGS = -std=c99 -Wall -Wextra -Wstrict-aliasing -fstrict-aliasing -O3 -DNDEBUG
# LDFLAGS =
LDFLAGS = -s
SRCS = main.c dns.c dnl.c net.c
OBJS = $(SRCS:.c=.o)
LIBS = -lm
MAIN = chinadns-ng
DESTDIR = /usr/local/bin

.PHONY: all install uninstall clean

all: $(MAIN)

install: $(MAIN)
	install -d $(DESTDIR)
	install -m 0755 $(MAIN) $(DESTDIR)

uninstall:
	$(RM) $(DESTDIR)/$(MAIN)

clean:
	$(RM) *.o $(MAIN)

$(MAIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(MAIN) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
