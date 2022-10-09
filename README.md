# order-book
Construct an order book using Coinbase websocket API to learn some C++

It includes a custom websocket implementation including TLS termination using OpenSSL.

It has one thread connecting to Coinbase websocket API to get market data and construct order book.

It has another thread running an HTTP server to display the order book.

The main thread displays the order book at one-second interval.

## Dependencies
sudo apt-get install libssl-dev

sudo apt-get install g++

git clone https://github.com/nlohmann/json.git

git clone https://github.com/etr/libhttpserver.git

sudo apt install libmicrohttpd-dev

sudo apt install doxygen

## Acknowledgement
I learnt how to implement a websocket client from https://github.com/machinezone/IXWebSocket

I learnt how to construct an order book from Coinbase websocket API data from article http://www.brianamadio.com/2020/12/11/building-a-real-time-order-book-from-the-coinbase-websocket-api-with-clojure/
