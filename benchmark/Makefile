CXXFLAGS = -std=c++11 -O2 -I..

THEAD_POOL_COUNT = 16

BENCH = bombardier -c 10 -d 5s localhost:8080
MONITOR = ali http://localhost:8080

# cpp-httplib
bench: server
	@echo "--------------------\n cpp-httplib latest\n--------------------\n"
	@./server & export PID=$$!; $(BENCH); kill $${PID}
	@echo ""

monitor: server
	@./server & export PID=$$!; $(MONITOR); kill $${PID}

run : server
	@./server

server : cpp-httplib/main.cpp ../httplib.h
	g++ -o $@ $(CXXFLAGS) -DCPPHTTPLIB_THREAD_POOL_COUNT=$(THEAD_POOL_COUNT) cpp-httplib/main.cpp

# cpp-httplib
bench-base: server-base
	@echo "---------------------\n cpp-httplib v0.17.0\n---------------------\n"
	@./server-base & export PID=$$!; $(BENCH); kill $${PID}
	@echo ""

monitor-base: server-base
	@./server-base & export PID=$$!; $(MONITOR); kill $${PID}

run-base : server-base
	@./server-base

server-base : cpp-httplib-base/main.cpp cpp-httplib-base/httplib.h
	g++ -o $@ $(CXXFLAGS) -DCPPHTTPLIB_THREAD_POOL_COUNT=$(THEAD_POOL_COUNT) cpp-httplib-base/main.cpp

# crow
bench-crow: server-crow
	@echo "-------------\n Crow v1.2.0\n-------------\n"
	@./server-crow & export PID=$$!; $(BENCH); kill $${PID}
	@echo ""

monitor-crow: server-crow
	@./server-crow & export PID=$$!; $(MONITOR); kill $${PID}

run-crow : server-crow
	@./server-crow

server-crow : crow/main.cpp
	g++ -o $@ $(CXXFLAGS) crow/main.cpp

# misc
bench-all: bench-crow bench bench-base

issue:
	$(BENCH)

clean:
	rm -rf server*
