
#CXX = clang++
CXXFLAGS = -ggdb -O0 -std=c++11 -DGTEST_USE_OWN_TR1_TUPLE -I.. -I. -Wall -Wextra -Wtype-limits
OPENSSL_DIR = /usr/local/opt/openssl
OPENSSL_SUPPORT = -DCPPHTTPLIB_OPENSSL_SUPPORT -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib -lssl -lcrypto
ZLIB_SUPPORT = -DCPPHTTPLIB_ZLIB_SUPPORT -lz

all : test
	./test

proxy : test_proxy
	./test_proxy

test : test.cc ../httplib.h Makefile cert.pem
	$(CXX) -o test $(CXXFLAGS) test.cc gtest/gtest-all.cc gtest/gtest_main.cc $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT) -pthread

test_proxy : test_proxy.cc ../httplib.h Makefile cert.pem
	$(CXX) -o test_proxy $(CXXFLAGS) test_proxy.cc gtest/gtest-all.cc gtest/gtest_main.cc $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT) -pthread

cert.pem:
	openssl genrsa 2048 > key.pem
	openssl req -new -batch -config test.conf -key key.pem | openssl x509 -days 3650 -req -signkey key.pem > cert.pem
	openssl genrsa 2048 > rootCA.key.pem
	openssl req -x509 -new -batch -config test.rootCA.conf -key rootCA.key.pem -days 1024 > rootCA.cert.pem
	openssl genrsa 2048 > client.key.pem
	openssl req -new -batch -config test.conf -key client.key.pem | openssl x509 -days 370 -req -CA rootCA.cert.pem -CAkey rootCA.key.pem -CAcreateserial > client.cert.pem
	#c_rehash .

clean:
	rm -f test test_proxy pem *.0 *.1 *.srl
