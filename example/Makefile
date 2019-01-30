
CC = clang++
CFLAGS = -std=c++14 -I.. -Wall -Wextra -lpthread
#OPENSSL_SUPPORT = -DCPPHTTPLIB_OPENSSL_SUPPORT -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
ZLIB_SUPPORT = -DCPPHTTPLIB_ZLIB_SUPPORT -lz

all: server client hello simplesvr benchmark

server : server.cc ../httplib.h Makefile
	$(CC) -o server $(CFLAGS) server.cc $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT)

client : client.cc ../httplib.h Makefile
	$(CC) -o client $(CFLAGS) client.cc $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT)

hello : hello.cc ../httplib.h Makefile
	$(CC) -o hello $(CFLAGS) hello.cc $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT)

simplesvr : simplesvr.cc ../httplib.h Makefile
	$(CC) -o simplesvr $(CFLAGS) simplesvr.cc $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT)

benchmark : benchmark.cc ../httplib.h Makefile
	$(CC) -o benchmark $(CFLAGS) benchmark.cc $(OPENSSL_SUPPORT) $(ZLIB_SUPPORT)

pem:
	openssl genrsa 2048 > key.pem
	openssl req -new -key key.pem | openssl x509 -days 3650 -req -signkey key.pem > cert.pem

clean:
	rm server client hello simplesvr *.pem
