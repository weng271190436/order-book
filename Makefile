CXXFLAGS = -std=c++20 -Wall -g
LDLIBS = -lstdc++
LDFLAGS = -L/usr/local/ssl/lib
export LD_LIBRARY_PATH=/usr/local/lib
.PHONY: all clean
all: orderbook tlsexample ixwebsocket test
clean:
	-rm  orderbook tlsexample ixwebsocket test *.o
orderbook: orderbook.o -lpthread -lssl -lcrypto -lhttpserver
orderbook.o: orderbook.cpp
tlsexample: tlsexample.o -lssl -lcrypto
tlsexample.o: tlsexample.cpp
ixwebsocket: ixwebsocket.o -lixwebsocket -ldl -lm -lpthread -lz -lssl -lcrypto
ixwebsocket.o: ixwebsocket.cpp
test: test.o -lpthread -lssl -lcrypto
test.o: test.cpp