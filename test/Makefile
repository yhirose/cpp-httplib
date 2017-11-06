
CC = clang++
CFLAGS = -std=c++14 -DGTEST_USE_OWN_TR1_TUPLE -I.. -I.
#OPENSSL_SUPPORT = -DCPPHTTPLIB_OPENSSL_SUPPORT -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto

all : test
	./test

test : test.cc ../httplib.h Makefile
	$(CC) -o test $(CFLAGS) test.cc gtest/gtest-all.cc gtest/gtest_main.cc $(OPENSSL_SUPPORT)

pem:
	openssl genrsa 2048 > key.pem
	openssl req -new -key key.pem | openssl x509 -days 3650 -req -signkey key.pem > cert.pem

clean:
	rm test *.pem
