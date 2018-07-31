
CC = clang++
#CC = g++

CFLAGS = -ggdb -O0 -std=c++11 -DGTEST_USE_OWN_TR1_TUPLE -I.. -I. -Wall -Wextra
OPENSSL_SUPPORT = -DCPPHTTPLIB_OPENSSL_SUPPORT -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
ZLIB_SUPPORT = -DCPPHTTPLIB_ZLIB_SUPPORT -lz

all : test
	./test

test : test.cc ../httplib.h Makefile cert.pem
	$(CC) -o test $(CFLAGS) test.cc gtest/gtest-all.cc gtest/gtest_main.cc $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT) -lpthread

cert.pem:
	openssl genrsa 2048 > key.pem
	openssl req -new -batch -config test.conf -key key.pem | openssl x509 -days 3650 -req -signkey key.pem > cert.pem

clean:
	rm -f test *.pem
