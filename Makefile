CXXFLAGS = -std=gnu++0x -Wall -g
LDLIBS = -lstdc++ -lssl -lcrypto
LDFLAGS = -L/usr/local/ssl/lib
.PHONY: all clean
all: example-client example-client-cpp11 boost-websocket
clean:
	-rm  example-client example-client-cpp11 boost-websocket *.o
example-client-cpp11: example-client-cpp11.o easywsclient.o
example-client-cpp11.o: example-client-cpp11.cpp easywsclient.hpp
example-client: example-client.o easywsclient.o
example-client.o: example-client.cpp easywsclient.hpp
easywsclient.o: easywsclient.cpp easywsclient.hpp
boost-websocket: boost-websocket.o -lpthread
boost-websocket.o: boost-websocket.cpp