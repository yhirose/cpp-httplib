CXXFLAGS = -std=c++11 -O2 -I..

THEAD_POOL_COUNT = 16

BENCH_CMD = bombardier -c 8 -d 5s localhost:8080
# BENCH_CMD = wrk -d 5s http://localhost:8080

# cpp-httplib
bench: server
	@./server & export PID=$$!; $(BENCH_CMD); kill $${PID}

run : server
	@./server

server : cpp-httplib/main.cpp ../httplib.h
	g++ -o $@ $(CXXFLAGS) -DCPPHTTPLIB_THREAD_POOL_COUNT=$(THEAD_POOL_COUNT) cpp-httplib/main.cpp

# crow
bench-crow: server-crow
	@./server-crow & export PID=$$!; $(BENCH_CMD); kill $${PID}

run-crow : server-crow
	@./server-crow

server-crow : crow/main.cpp
	g++ -o $@ $(CXXFLAGS) crow/main.cpp

# flask
bench-flask:
	@FLASK_APP=flask/main.py flask run --port=8080 & export PID=$$!; $(BENCH_CMD); kill $${PID}

run-flask:
	@FLASK_APP=flask/main.py flask run --port=8080

# misc
bench-all: bench bench-crow bench-flask

clean:
	rm -rf server*
