PROJ=ipk-l4-scan

CC=gcc
CFLAGS=-Wall -Wextra -O2 -MMD -Werror -Wpedantic -g
LDFLAGS=-lpcap

SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))
DEPS=$(patsubst %.c,%.d,$(SRCS))

$(PROJ): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

-include $(DEPS)

.PHONY: clean
clean:
	rm -rf $(PROJ) $(OBJS) $(DEPS)
