# pong — a minimal, dependency-free ICMP/ping network scanner
#
# Targets:
#   make            release build (default)
#   make debug      ASan/UBSan build for development
#   make native     build with -march=native (fastest, host-specific)
#   make check      rebuild with -Werror and run tests/smoke.sh
#   make install    install to $(PREFIX)/bin (default /usr/local)
#   make uninstall  remove the installed binary
#   make clean      remove build artifacts
#
# Optional overrides (example):
#   make BUILD=debug ARCH=native WERROR=1 EXTRA_CFLAGS="-fno-omit-frame-pointer"

CC        ?= cc
BUILD     ?= release
ARCH      ?=
WERROR    ?= 0
PREFIX    ?= /usr/local
DESTDIR   ?=

BIN := pong
SRC := src

SRCS := $(SRC)/main.c $(SRC)/ping.c $(SRC)/socks5.c $(SRC)/checksum.c $(SRC)/util.c
OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)
HDRS := $(wildcard $(SRC)/*.h)

WARNINGS := -Wall -Wextra -Wpedantic -Wshadow -Wpointer-arith \
            -Wwrite-strings -Wmissing-prototypes -Wstrict-prototypes \
            -Wformat=2 -Wimplicit-fallthrough -Wundef

CPPFLAGS := -I$(SRC)

ifeq ($(BUILD),debug)
# Instrumented build: AddressSanitizer + UndefinedBehaviorSanitizer.
CFLAGS  := -std=c11 -O0 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS := -fsanitize=address,undefined
else
# Release build: aggressive optimization plus standard hardening.
CFLAGS  := -std=c11 -O3 -flto -fno-plt -fomit-frame-pointer \
           -fstack-protector-strong -fPIE
LDFLAGS := -flto -pie -Wl,-z,relro,-z,now,-z,noexecstack
CPPFLAGS += -D_FORTIFY_SOURCE=2
endif

CFLAGS += $(WARNINGS) $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)
ifneq ($(ARCH),)
CFLAGS += -march=$(ARCH)
endif
ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

$(SRC)/%.o: $(SRC)/%.c $(HDRS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

.PHONY: all clean debug native check install uninstall

debug:
	$(MAKE) BUILD=debug

native:
	$(MAKE) ARCH=native

check:
	$(MAKE) clean all WERROR=1
	./tests/smoke.sh ./$(BIN)

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(OBJS) $(DEPS) $(BIN)
