
CC = clang++
CFLAGS = -std=c++14 -I..
#OPENSSL_SUPPORT = -DCPPHTTPLIB_OPENSSL_SUPPORT -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto

all: server client hello simplesvr

server : server.cc ../httplib.h
	$(CC) -o server $(CFLAGS) server.cc $(OPENSSL_SUPPORT)

client : client.cc ../httplib.h
	$(CC) -o client $(CFLAGS) client.cc $(OPENSSL_SUPPORT)

hello : hello.cc ../httplib.h
	$(CC) -o hello $(CFLAGS) hello.cc $(OPENSSL_SUPPORT)

simplesvr : simplesvr.cc ../httplib.h
	$(CC) -o simplesvr $(CFLAGS) simplesvr.cc $(OPENSSL_SUPPORT)

pem:
	openssl genrsa 2048 > key.pem
	openssl req -new -key key.pem | openssl x509 -days 3650 -req -signkey key.pem > cert.pem

clean:
	rm server client hello simplesvr *.pem
