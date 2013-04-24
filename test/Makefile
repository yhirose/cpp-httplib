
USE_CLANG = 1

ifdef USE_CLANG
CC = clang++
CCFLAGS = -std=c++0x -stdlib=libc++ -g -DGTEST_USE_OWN_TR1_TUPLE
else
CC = g++-4.7
CCFLAGS = -std=c++11 -g
endif

all : test
	./test

test : test.cc ../httplib.h
	$(CC) -o test $(CCFLAGS) -I.. -I. test.cc gtest/gtest-all.cc gtest/gtest_main.cc
