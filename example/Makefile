
USE_CLANG = 1

ifdef USE_CLANG
CC = clang++
CFLAGS = -std=c++0x -stdlib=libc++ -g
else
CC = g++
CFLAGS = -std=c++11 -g
endif

all: sample hello

sample : sample.cc ../httplib.h
	$(CC) -o sample $(CFLAGS) -I.. sample.cc

hello : hello.cc ../httplib.h
	$(CC) -o hello $(CFLAGS) -I.. hello.cc
