CXXFLAGS = -std=c++20 -Wall -g
LDLIBS = -lstdc++
LDFLAGS = -L/usr/local/ssl/lib
export LD_LIBRARY_PATH=/usr/local/lib
.PHONY: all clean
all: orderbook tlsexample ixwebsocket
clean:
	-rm  orderbook tlsexample ixwebsocket *.o
orderbook: orderbook.o -lpthread -lssl -lcrypto -lhttpserver
orderbook.o: orderbook.cpp
tlsexample: tlsexample.o -lssl -lcrypto
tlsexample.o: tlsexample.cpp
ixwebsocket: ixwebsocket.o -lixwebsocket -ldl -lm -lpthread -lz -lssl -lcrypto
ixwebsocket.o: ixwebsocket.cpp