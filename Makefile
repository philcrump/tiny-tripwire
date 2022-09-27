CC := gcc
COPT := -O2 -march=core-avx2
CFLAGS := -Wall -Wextra -Wpedantic -Wunused -std=gnu11 -D_GNU_SOURCE -ggdb
LDFLAGS := -lm -lrt -pthread -lpcap -lcurl -ljson-c

C_SRCS := src/main.c \
			src/config.c \
			src/email.c \
			src/util/timing.c

OBJS := ${C_SRCS:.c=.o}
DEPS := ${C_SRCS:.c=.d}

all: _print_banner ttw

debug: COPT = -Og
debug: CFLAGS += -fno-omit-frame-pointer
debug: all

werror: CFLAGS += -Werror
werror: all

%.o: %.c
	@echo "  CC     "$<
	@$(CC) $(COPT) $(CFLAGS) $(INC) -MMD -MP -c "$<" -o "$@"

-include $(DEPS)

ttw: $(OBJS)
	@echo "  LD     "$@
	@$(CC) $(COPT) $(CFLAGS) $(OBJS) -o $@ ${LDFLAGS}

_print_banner:
	@echo "Compiling with GCC $(shell $(CC) -dumpfullversion) on $(shell $(CC) -dumpmachine)"

clean:
	@rm -rfv ttw src/*.o src/*.d src/*/*.o src/*/*.d

.PHONY: all clean
