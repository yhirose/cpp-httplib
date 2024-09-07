CXXFLAGS = -std=c++11 -O2 -I..

THEAD_POOL_COUNT = 16

BENCH = bombardier -l -c 10 -d 5s localhost:8080
MONITOR = ali http://localhost:8080

# cpp-httplib
bench: server
	@./server & export PID=$$!; $(BENCH); kill $${PID}

monitor: server
	@./server & export PID=$$!; $(MONITOR); kill $${PID}

run : server
	@./server

server : cpp-httplib/main.cpp ../httplib.h
	g++ -o $@ $(CXXFLAGS) -DCPPHTTPLIB_THREAD_POOL_COUNT=$(THEAD_POOL_COUNT) cpp-httplib/main.cpp

# crow
bench-crow: server-crow
	@./server-crow & export PID=$$!; $(BENCH); kill $${PID}

monitor-crow: server-crow
	@./server-crow & export PID=$$!; $(MONITOR); kill $${PID}

run-crow : server-crow
	@./server-crow

server-crow : crow/main.cpp
	g++ -o $@ $(CXXFLAGS) crow/main.cpp

# misc
issue:
	$(BENCH)

clean:
	rm -rf server*
