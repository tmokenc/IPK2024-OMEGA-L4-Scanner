PROJ=ipk-l4-scan

CC=gcc
CFLAGS=-Wall -Wextra -O2 -MMD -Werror -Wpedantic -g

SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))
DEPS=$(patsubst %.c,%.d,$(SRCS))

$(PROJ): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

pack:
	zip xnguye27.zip -r img/*.png *.c *.h Makefile README.md CHANGELOG.md LICENSE

-include $(DEPS)

.PHONY: clean
clean:
	rm -rf $(PROJ) $(OBJS) $(DEPS)
