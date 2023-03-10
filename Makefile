CC = gcc

ifeq ($(findstring clang,$(shell $(CC) --version)),)
LTOFLAGS = -flto -flto-partition=none
else
LTOFLAGS = -flto
endif

ifdef DEBUG
CFLAGS = -pipe -std=c99 -Wall -Wextra -Og -ggdb3
LDFLAGS = -pipe
else
CFLAGS = -pipe -std=c99 -Wall -Wextra -O3 $(LTOFLAGS) -DNDEBUG
LDFLAGS = -pipe -O3 $(LTOFLAGS) -s
endif

ifdef STATIC
LDFLAGS += -static
endif

ifdef LDDIRS
LDFLAGS += $(LDDIRS)
endif

SRCS = main.c opt.c dns.c dnl.c net.c
OBJS = $(SRCS:.c=.o)
LDLIBS = -lm
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
	$(RM) *.o *.gch $(MAIN)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

$(MAIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(MAIN) $(OBJS) $(LDLIBS)
