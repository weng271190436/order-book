#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXUserAgent.h>
#include <iostream>
#include <sstream>

int main() {
    ix::WebSocket webSocket;
    std::string url("wss://ws-feed.exchange.coinbase.com:443");
    webSocket.setUrl(url);
    webSocket.setPingInterval(45);

    std::cout << ix::userAgent() << std::endl;
    std::cout << "Connecting to " << url << "..." << std::endl;

    // Setup a callback to be fired (in a background thread, watch out for race conditions !)
    // when a message or an event (open, close, error) is received
    webSocket.setOnMessageCallback([](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Open)
            {
                std::cout << "Connection opened" << std::endl;
            }
            else if (msg->type == ix::WebSocketMessageType::Close)
            {
                std::cout << "Connection closed" << std::endl;
            }
            else if (msg->type == ix::WebSocketMessageType::Error)
            {
                std::cout << "Error: " << msg->errorInfo.reason << std::endl;
            }
            else if (msg->type == ix::WebSocketMessageType::Message)
            {
                std::cout << "Message received: " << msg->str << std::endl;
            }
        }
    );

    webSocket.start();
    sleep(1);
    std::string product_id = "BTC-USD";
    std::ostringstream ss;
    ss << "{ \"type\": \"subscribe\", \"channels\": [ { \"name\": \"heartbeat\", \"product_ids\": [ \"" << product_id << "\" ] }, { \"name\": \"level2\", \"product_ids\": [ \"" << product_id << "\" ] } ] }";
    std::string msg = ss.str();
    webSocket.send(msg);
    sleep(10);
    webSocket.stop();
    return 0;
}
