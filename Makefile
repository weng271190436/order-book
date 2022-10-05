CXXFLAGS = -std=c++17 -Wall -g
LDLIBS = -lstdc++ -lssl -lcrypto
LDFLAGS = -L/usr/local/ssl/lib
.PHONY: all clean
all: websocketpp
clean:
	-rm  websocketpp *.o
websocketpp: websocketpp.o -lpthread
websocketpp.o: websocketpp.cpp