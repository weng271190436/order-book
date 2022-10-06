CXXFLAGS = -std=c++20 -Wall -g
LDLIBS = -lstdc++ -lssl -lcrypto
LDFLAGS = -L/usr/local/ssl/lib
.PHONY: all clean
all: orderbook
clean:
	-rm  orderbook *.o
orderbook: orderbook.o -lpthread
orderbook.o: orderbook.cpp