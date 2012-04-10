BINDIR=bin
INCDIR=include
SRCDIR=src
TESTDIR=test

FLAGS=-ansi
CARDFLAGS=$(FLAGS) -I$(INCDIR)
SIMFLAGS=$(FLAGS) -g -I$(INCDIR) -DSIMULATOR -DTEST

HEADERS=$(wildcard $(INCDIR)/*.h)
SOURCES=$(wildcard $(SRCDIR)/*.c)

SMARTCARD=$(BINDIR)/idemix.smartcard.hzx
SIMULATOR=$(BINDIR)/idemix.simulator.hzx

SOURCES_crypto_compute_hash=$(TESTDIR)/crypto_compute_hash.c $(SRCDIR)/crypto_helper.c $(SRCDIR)/funcs_helper.c
TEST_crypto_compute_hash=$(BINDIR)/crypto_compute_hash.hzx

TEST=$(TEST_crypto_compute_hash)

all: simulator smartcard

simulator: $(HEADERS) $(SOURCES) $(SIMULATOR)

$(SIMULATOR): $(HEADERS) $(SOURCES)
	hcl $(SIMFLAGS) $(SOURCES) -o $(SIMULATOR)

smartcard: $(HEADERS) $(SOURCES) $(SMARTCARD)

$(SMARTCARD): $(HEADERS) $(SOURCES)
	hcl $(CARDFLAGS) $(SOURCES) -o $(SMARTCARD)

test: $(TEST)

$(TEST_crypto_compute_hash): $(HEADERS) $(SOURCES_crypto_compute_hash)
	hcl $(SIMFLAGS) $(SOURCES_crypto_compute_hash) -o $(TEST_crypto_compute_hash)

clean:
	rm -rf $(BINDIR)/* $(SRCDIR)/*~ $(INCDIR)/*~

.PHONY: all clean simulator smartcard test
