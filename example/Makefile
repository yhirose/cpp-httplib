
USE_CLANG = 1

ifdef USE_CLANG
CC = clang++
CFLAGS = -std=c++0x -stdlib=libc++
else
CC = g++
CFLAGS = -std=c++11
endif

sample : sample.cc ../httpsvrkit.h
	$(CC) -o sample $(CFLAGS) -I.. sample.cc

.PHONY : test
test: sample
	./sample
