
USE_CLANG = 1

ifdef USE_CLANG
CC = clang++
CFLAGS = -std=c++0x -stdlib=libc++ -g
else
CC = g++
CFLAGS = -std=c++11 -g
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
