CXXFLAGS = -std=c++20 -Wall -g
LDLIBS = -lstdc++
LDFLAGS = -L/usr/local/ssl/lib
export LD_LIBRARY_PATH=/usr/local/lib
.PHONY: all clean
all: orderbook
clean:
	-rm  orderbook *.o
orderbook: orderbook.o -lpthread -lssl -lcrypto -lhttpserver
orderbook.o: orderbook.cpp
