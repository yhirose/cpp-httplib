CXXFLAGS = -O2 -I..

CPPHTTPLIB_CXXFLAGS = -std=c++11
CROW_CXXFLAGS = -std=c++17

CPPHTTPLIB_FLAGS = -DCPPHTTPLIB_THREAD_POOL_COUNT=16

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
	@g++ -o $@ $(CXXFLAGS) $(CPPHTTPLIB_CXXFLAGS) $(CPPHTTPLIB_FLAGS) cpp-httplib/main.cpp

# crow
bench-crow: server-crow
	@echo "-------------\n Crow v1.3.1\n-------------\n"
	@./server-crow & export PID=$$!; $(BENCH); kill $${PID}
	@echo ""

monitor-crow: server-crow
	@./server-crow & export PID=$$!; $(MONITOR); kill $${PID}

run-crow : server-crow
	@./server-crow

server-crow : crow/main.cpp crow/crow_all.h
	@g++ -o $@ $(CXXFLAGS) $(CROW_CXXFLAGS) crow/main.cpp

# misc
build: server server-crow

bench-all: bench-crow bench

issue:
	bombardier -c 10 -d 30s localhost:8080

clean:
	rm -rf server*
