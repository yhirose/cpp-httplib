CXX = clang++
CXXFLAGS = -g -std=c++11 -I. -Wall -Wextra -Wtype-limits -Wconversion -Wshadow # -fno-exceptions -DCPPHTTPLIB_NO_EXCEPTIONS -fsanitize=address

PREFIX ?= $(shell brew --prefix)

OPENSSL_DIR = $(PREFIX)/opt/openssl@3
OPENSSL_SUPPORT = -DCPPHTTPLIB_OPENSSL_SUPPORT -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib -lssl -lcrypto

ifneq ($(OS), Windows_NT)
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S), Darwin)
		OPENSSL_SUPPORT += -DCPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN -framework CoreFoundation -framework Security
	endif
endif

ZLIB_SUPPORT = -DCPPHTTPLIB_ZLIB_SUPPORT -lz

BROTLI_DIR = $(PREFIX)/opt/brotli
BROTLI_SUPPORT = -DCPPHTTPLIB_BROTLI_SUPPORT -I$(BROTLI_DIR)/include -L$(BROTLI_DIR)/lib -lbrotlicommon -lbrotlienc -lbrotlidec

TEST_ARGS = gtest/gtest-all.cc gtest/gtest_main.cc $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT) $(BROTLI_SUPPORT) -pthread -lcurl

# By default, use standalone_fuzz_target_runner.
# This runner does no fuzzing, but simply executes the inputs
# provided via parameters.
# Run e.g. "make all LIB_FUZZING_ENGINE=/path/to/libFuzzer.a"
# to link the fuzzer(s) against a real fuzzing engine.
# OSS-Fuzz will define its own value for LIB_FUZZING_ENGINE.
LIB_FUZZING_ENGINE ?= standalone_fuzz_target_runner.o

all : test test_split
	./test

proxy : test_proxy
	./test_proxy

test : test.cc include_httplib.cc ../httplib.h Makefile cert.pem
	$(CXX) -o $@ -I.. $(CXXFLAGS) test.cc include_httplib.cc $(TEST_ARGS)

# Note: The intention of test_split is to verify that it works to compile and
# link the split httplib.h, so there is normally no need to execute it.
test_split : test.cc ../httplib.h httplib.cc Makefile cert.pem
	$(CXX) -o $@ $(CXXFLAGS) test.cc httplib.cc $(TEST_ARGS)

test_proxy : test_proxy.cc ../httplib.h Makefile cert.pem
	$(CXX) -o $@ -I.. $(CXXFLAGS) test_proxy.cc $(TEST_ARGS)

# Runs server_fuzzer.cc based on value of $(LIB_FUZZING_ENGINE).
# Usage: make fuzz_test LIB_FUZZING_ENGINE=/path/to/libFuzzer
fuzz_test: server_fuzzer
	./server_fuzzer fuzzing/corpus/*

# Fuzz target, so that you can choose which $(LIB_FUZZING_ENGINE) to use.
server_fuzzer : fuzzing/server_fuzzer.cc ../httplib.h standalone_fuzz_target_runner.o
	$(CXX) -o $@ -I.. $(CXXFLAGS) $< $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT) $(BROTLI_SUPPORT) $(LIB_FUZZING_ENGINE) -pthread

# Standalone fuzz runner, which just reads inputs from fuzzing/corpus/ dir and
# feeds it to server_fuzzer.
standalone_fuzz_target_runner.o : fuzzing/standalone_fuzz_target_runner.cpp
	$(CXX) -o $@ -I.. $(CXXFLAGS) -c $<

httplib.cc : ../httplib.h
	python3 ../split.py -o .

cert.pem:
	./gen-certs.sh

clean:
	rm -f test test_split test_proxy server_fuzzer *.pem *.0 *.o *.1 *.srl httplib.h httplib.cc

