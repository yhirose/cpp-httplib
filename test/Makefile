#CXX = clang++
CXXFLAGS = -g -std=c++11 -I. -Wall -Wextra -Wtype-limits -Wconversion #-fsanitize=address

OPENSSL_DIR = /usr/local/opt/openssl@1.1
OPENSSL_SUPPORT = -DCPPHTTPLIB_OPENSSL_SUPPORT -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib -lssl -lcrypto

ZLIB_SUPPORT = -DCPPHTTPLIB_ZLIB_SUPPORT -lz

BROTLI_DIR = /usr/local/opt/brotli
BROTLI_SUPPORT = -DCPPHTTPLIB_BROTLI_SUPPORT -I$(BROTLI_DIR)/include -L$(BROTLI_DIR)/lib -lbrotlicommon -lbrotlienc -lbrotlidec

TEST_ARGS = gtest/gtest-all.cc gtest/gtest_main.cc $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT) $(BROTLI_SUPPORT) -pthread

all : test test_split
	./test
# Note: The intention of test_split is to verify that it works to compile and
# link the split httplib.h, so there is normally no need to execute it.

proxy : test_proxy
	./test_proxy

test : test.cc include_httplib.cc ../httplib.h Makefile cert.pem
	$(CXX) -o $@ -I.. $(CXXFLAGS) test.cc include_httplib.cc $(TEST_ARGS)

test_split : test.cc ../httplib.h httplib.cc Makefile cert.pem
	$(CXX) -o $@ $(CXXFLAGS) test.cc httplib.cc $(TEST_ARGS)

test_proxy : test_proxy.cc ../httplib.h Makefile cert.pem
	$(CXX) -o $@ -I.. $(CXXFLAGS) test_proxy.cc $(TEST_ARGS)

httplib.cc : ../httplib.h
	python3 ../split.py -o .

cert.pem:
	openssl genrsa 2048 > key.pem
	openssl req -new -batch -config test.conf -key key.pem | openssl x509 -days 3650 -req -signkey key.pem > cert.pem
	openssl req -x509 -config test.conf -key key.pem -sha256 -days 3650 -nodes -out cert2.pem -extensions SAN
	openssl genrsa 2048 > rootCA.key.pem
	openssl req -x509 -new -batch -config test.rootCA.conf -key rootCA.key.pem -days 1024 > rootCA.cert.pem
	openssl genrsa 2048 > client.key.pem
	openssl req -new -batch -config test.conf -key client.key.pem | openssl x509 -days 370 -req -CA rootCA.cert.pem -CAkey rootCA.key.pem -CAcreateserial > client.cert.pem
	#c_rehash .

clean:
	rm -f test test_proxy pem *.0 *.1 *.srl httplib.h httplib.cc
