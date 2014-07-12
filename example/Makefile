
USE_CLANG = 1

ifdef USE_CLANG
CC = clang++
CFLAGS = -std=c++1y -stdlib=libc++ -g
else
CC = g++-4.9
CFLAGS = -std=c++1y -g
endif

all: server client hello simplesvr

server : server.cc ../httplib.h
	$(CC) -o server $(CFLAGS) -I.. server.cc

client : client.cc ../httplib.h
	$(CC) -o client $(CFLAGS) -I.. client.cc

hello : hello.cc ../httplib.h
	$(CC) -o hello $(CFLAGS) -I.. hello.cc

simplesvr : simplesvr.cc ../httplib.h
	$(CC) -o simplesvr $(CFLAGS) -I.. simplesvr.cc
