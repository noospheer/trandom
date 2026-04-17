CC       ?= cc
CFLAGS   ?= -O3 -march=native -Wall -Wextra
LDFLAGS  ?=
PTHREAD   = -pthread -lpthread

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
LIBDIR   ?= $(PREFIX)/lib
INCDIR   ?= $(PREFIX)/include
UNITDIR  ?= /etc/systemd/system
CONFDIR  ?= /etc/default

# CUSE = required (default) | no
#   required: libfuse3-dev must be present; build fails loudly if absent
#   no:       skip /dev/trandom bridge, build core only
CUSE     ?= required

FUSE_CFLAGS := $(shell pkg-config --cflags fuse3 2>/dev/null)
FUSE_LIBS   := $(shell pkg-config --libs   fuse3 2>/dev/null)
HAVE_FUSE   := $(if $(FUSE_LIBS),yes,)

ifeq ($(CUSE),required)
  ifneq ($(HAVE_FUSE),yes)
    $(error libfuse3-dev not found — CUSE is required by default. Install it (apt install libfuse3-dev, dnf install fuse3-devel) and rebuild, or explicitly opt out with: make CUSE=no)
  endif
endif

CORE_TARGETS = trandomd libtrandom.so trctl
FUSE_TARGETS = $(if $(filter-out no,$(CUSE)),$(if $(HAVE_FUSE),trandom-cuse,),)

all: $(CORE_TARGETS) $(FUSE_TARGETS)
	@if [ "$(CUSE)" = "no" ]; then \
		echo "note: built with CUSE=no — /dev/trandom device NOT available"; \
	fi

trandomd: trandomd.c trandom.h
	$(CC) $(CFLAGS) -mpclmul -msse4.1 -o $@ trandomd.c $(LDFLAGS) $(PTHREAD)

libtrandom.so: libtrandom.c trandom.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ libtrandom.c $(LDFLAGS) $(PTHREAD)

trctl: trctl.c libtrandom.so trandom.h
	$(CC) $(CFLAGS) -o $@ trctl.c -L. -ltrandom -Wl,-rpath,'$$ORIGIN' $(LDFLAGS) $(PTHREAD)

# CUSE links against system libfuse3 (built against system glibc). If the
# default CC is a non-system toolchain (conda, Nix, sysroot SDK) its libc
# won't match. Force /usr/bin/gcc for just this target when present.
SYSCC := $(if $(wildcard /usr/bin/gcc),/usr/bin/gcc,$(CC))
trandom-cuse: trandom-cuse.c trandom.h
	@if [ "$(SYSCC)" != "/usr/bin/gcc" ]; then \
		echo "warning: /usr/bin/gcc not found; linking CUSE with $(CC) may fail against system libfuse3"; \
	fi
	$(SYSCC) $(CFLAGS) $(FUSE_CFLAGS) -L/usr/lib/x86_64-linux-gnu -o $@ trandom-cuse.c $(LDFLAGS) $(FUSE_LIBS) $(PTHREAD)

install: all
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCDIR) \
	           $(DESTDIR)$(UNITDIR) $(DESTDIR)$(CONFDIR)
	install -m 755 trandomd trctl $(DESTDIR)$(BINDIR)/
	install -m 755 libtrandom.so $(DESTDIR)$(LIBDIR)/
	install -m 644 trandom.h     $(DESTDIR)$(INCDIR)/
	install -m 644 systemd/trandomd.service $(DESTDIR)$(UNITDIR)/
	install -m 644 systemd/trandom.default  $(DESTDIR)$(CONFDIR)/trandom.example
	# Create default config only if none exists — don't stomp user edits.
	@if [ ! -f $(DESTDIR)$(CONFDIR)/trandom ]; then \
		install -m 644 systemd/trandom.default $(DESTDIR)$(CONFDIR)/trandom; \
		echo "installed: $(DESTDIR)$(CONFDIR)/trandom (config)"; \
	else \
		echo "preserved: existing $(DESTDIR)$(CONFDIR)/trandom (example at $(DESTDIR)$(CONFDIR)/trandom.example)"; \
	fi
	# Create system user if not already present.
	@if ! getent passwd trandom >/dev/null 2>&1; then \
		useradd --system --no-create-home --shell /usr/sbin/nologin --user-group trandom && \
		echo "created: system user 'trandom'"; \
	else \
		echo "preserved: existing user 'trandom'"; \
	fi
	@if [ "$(HAVE_FUSE)" = "yes" ] && [ "$(CUSE)" != "no" ]; then \
		install -m 755 trandom-cuse $(DESTDIR)$(BINDIR)/; \
		install -m 644 systemd/trandom-cuse.service $(DESTDIR)$(UNITDIR)/; \
		echo "installed: /dev/trandom bridge"; \
	else \
		echo "installed: core only — /dev/trandom NOT available (rebuild with CUSE=required)"; \
	fi
	-ldconfig 2>/dev/null
	@echo ""
	@echo "Next steps:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now trandomd.service"
	@if [ "$(HAVE_FUSE)" = yes ] && [ "$(CUSE)" != "no" ]; then \
		echo "  sudo systemctl enable --now trandom-cuse.service"; \
	fi
	@echo "  sudo make check-install            # verify everything"

uninstall:
	-systemctl disable --now trandom-cuse.service 2>/dev/null
	-systemctl disable --now trandomd.service     2>/dev/null
	rm -f $(DESTDIR)$(BINDIR)/trandomd $(DESTDIR)$(BINDIR)/trctl $(DESTDIR)$(BINDIR)/trandom-cuse
	rm -f $(DESTDIR)$(LIBDIR)/libtrandom.so
	rm -f $(DESTDIR)$(INCDIR)/trandom.h
	rm -f $(DESTDIR)$(UNITDIR)/trandomd.service
	rm -f $(DESTDIR)$(UNITDIR)/trandom-cuse.service
	rm -f $(DESTDIR)$(CONFDIR)/trandom.example
	-rm -f /run/trandom/sock /run/trandom.sock
	-systemctl daemon-reload
	@echo "note: config $(DESTDIR)$(CONFDIR)/trandom and user 'trandom' preserved"
	@echo "      (remove manually if desired: rm $(DESTDIR)$(CONFDIR)/trandom; userdel trandom)"

# Post-install verification — confirms every link in the chain works,
# plus a quick statistical quality check on 1 MB of output.
# Waits up to 10 s for the socket + device to appear: running this immediately
# after `systemctl enable --now` otherwise races service startup.
check-install:
	@echo "=== trandom install check ==="
	@for i in $$(seq 1 50); do \
		{ [ -S /run/trandom/sock ] || [ -S /run/trandom.sock ]; } && [ -c /dev/trandom ] && break; \
		sleep 0.2; \
	done
	@printf "daemon service:  "
	@systemctl is-active trandomd.service 2>/dev/null || echo "INACTIVE"
	@printf "CUSE service:    "
	@systemctl is-active trandom-cuse.service 2>/dev/null || echo "INACTIVE (or built with CUSE=no)"
	@printf "socket:          "
	@if [ -S /run/trandom/sock ]; then echo "/run/trandom/sock exists"; \
	 elif [ -S /run/trandom.sock ]; then echo "/run/trandom.sock exists (legacy path)"; \
	 else echo "MISSING"; fi
	@printf "device:          "
	@[ -c /dev/trandom ] && echo "/dev/trandom is a char device ($$(stat -c %A /dev/trandom))" || echo "MISSING"
	@printf "read test:       "
	@n=$$(head -c 16 /dev/trandom 2>/dev/null | wc -c); \
	 [ "$$n" = "16" ] && echo "OK (16 bytes read)" || echo "FAILED ($$n bytes)"
	@echo ""
	@echo "=== quick quality audit (1 MB sample) ==="
	@head -c 1048576 /dev/trandom > /tmp/.trandom-check.bin 2>/dev/null || { \
		echo "could not read /dev/trandom — skip quality audit"; exit 0; }
	@./verify.py /tmp/.trandom-check.bin | tail -n +5 | head -n 11
	@rm -f /tmp/.trandom-check.bin
	@echo ""
	@echo "Run \`make verify\` for deeper audit (10 MB + per-source min-entropy)."

# Deep audit: stop existing daemon, start one with per-source raw dumps,
# pull 10 MB, run statistical + min-entropy tests on both extractor output
# and each source's pre-extractor samples.
verify: verify.py trandomd trctl libtrandom.so
	@set -e; \
	RAW=/tmp/trandom-verify-raw; OUT=/tmp/trandom-verify.bin; \
	SOCK=/tmp/trandom-verify.sock; \
	rm -rf "$$RAW" "$$OUT" "$$SOCK"; \
	echo "=== starting trandomd with raw-dump for each source ==="; \
	TRANDOM_RAW_DUMP_DIR="$$RAW" ./trandomd --sock="$$SOCK" --max-cpu=500 \
		>/tmp/trandom-verify.log 2>&1 & \
	DPID=$$!; sleep 0.5; \
	echo "=== pulling 10 MB extractor output ==="; \
	TRANDOM_SOCK="$$SOCK" LD_LIBRARY_PATH=. ./trctl 10000000 10000000 > "$$OUT"; \
	echo "sample: $$(wc -c < $$OUT) bytes"; \
	kill $$DPID 2>/dev/null; wait $$DPID 2>/dev/null || true; \
	echo ""; \
	./verify.py "$$OUT" "$$RAW"; \
	rm -rf "$$RAW" "$$OUT" "$$SOCK" /tmp/trandom-verify.log

clean:
	rm -f trandomd libtrandom.so trctl trandom-cuse

.PHONY: all install uninstall clean check-install verify
