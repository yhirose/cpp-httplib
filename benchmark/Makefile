CXXFLAGS = -std=c++14 -O2 -I..

THEAD_POOL_COUNT = 16
BENCH_FLAGS = -c 8 -d 5s

# cpp-httplib
bench: server
	@./server & export PID=$$!; bombardier $(BENCH_FLAGS) localhost:8080; kill $${PID}

server : cpp-httplib/main.cpp ../httplib.h
	g++ -o $@ $(CXXFLAGS) -DCPPHTTPLIB_THREAD_POOL_COUNT=$(THEAD_POOL_COUNT) cpp-httplib/main.cpp

run : server
	@./server

# crow
server-crow : crow/main.cpp
	g++ -o $@ $(CXXFLAGS) crow/main.cpp

bench-crow: server-crow
	@./server-crow & export PID=$$!; bombardier $(BENCH_FLAGS) localhost:8080; kill $${PID}

# flask
bench-flask:
	@FLASK_APP=flask/main.py flask run --port=8080 & export PID=$$!; bombardier $(BENCH_FLAGS) localhost:8080; kill $${PID}

# misc
bench-all: bench bench-crow bench-flask

clean:
	rm -rf server*
