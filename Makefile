PROJ=ipk-l4-scan

CC=gcc
CFLAGS=-Wall -Wextra -O2 -MMD -Werror -Wpedantic -g
LDFLAGS=-lpcap

SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))
DEPS=$(patsubst %.c,%.d,$(SRCS))

$(PROJ): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

pack:
	zip xnguye27.zip *.c *.h Makefile README.md CHANGELOG.md

-include $(DEPS)

.PHONY: clean
clean:
	rm -rf $(PROJ) $(OBJS) $(DEPS)
