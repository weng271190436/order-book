#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <set>
#include <mutex>

typedef websocketpp::client<websocketpp::config::asio_tls_client> client;
typedef websocketpp::lib::shared_ptr<boost::asio::ssl::context> context_ptr;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

using json = nlohmann::json;

typedef websocketpp::config::asio_client::message_type::ptr message_ptr;

struct order_book {
    std::map<double, double, std::greater<double>> bids;
    std::map<double, double> asks;
};

order_book b;
std::string product_id = "BTC-USD";
std::mutex m;

void on_open(client* c, websocketpp::connection_hdl hdl) {
    std::cout << "on_open" << std::endl;
    websocketpp::lib::error_code ec;
    std::ostringstream ss;
    ss << "{ \"type\": \"subscribe\", \"channels\": [ { \"name\": \"heartbeat\", \"product_ids\": [ \"" << product_id << "\" ] }, { \"name\": \"level2\", \"product_ids\": [ \"" << product_id << "\" ] } ] }";
    std::string msg = ss.str();
    c->send(hdl, msg, websocketpp::frame::opcode::text, ec);
    if (ec) {
        std::cout << "send failed because: " << ec.message() << std::endl;
    }
}

void on_message(client* c, websocketpp::connection_hdl hdl, message_ptr msg) {
    // std::cout << "on_message called with hdl: " << hdl.lock().get()
    //           << " and message: " << msg->get_payload()
    //           << std::endl;

    json message = json::parse(msg->get_payload());
    if (message["type"] == "snapshot") {
        for (auto it = message["bids"].begin(); it != message["bids"].end(); ++it) {
            // std::cout << product_id << " bid: price " << std::stod(it.value()[0].get<std::string>()) << " size " << std::stod(it.value()[1].get<std::string>()) << std::endl;
            m.lock();
            b.bids[std::stod(it.value()[0].get<std::string>())] = std::stod(it.value()[1].get<std::string>());
            m.unlock();
        }
        for (auto it = message["asks"].begin(); it != message["asks"].end(); ++it) {
            // std::cout << product_id << " ask: price " << std::stod(it.value()[0].get<std::string>()) << " size " << std::stod(it.value()[1].get<std::string>()) << std::endl;
            m.lock();
            b.asks[std::stod(it.value()[0].get<std::string>())] = std::stod(it.value()[1].get<std::string>());
            m.unlock();
        }
    } else if (message["type"] == "l2update") {
        // std::cout << message << std::endl;
        for (auto it = message["changes"].begin(); it != message["changes"].end(); ++it) {
            // std::cout << product_id << " change: " << it.value()[0].get<std::string>() << " price " << std::stod(it.value()[1].get<std::string>()) << " size " << std::stod(it.value()[2].get<std::string>()) << std::endl;
            std::string side = it.value()[0].get<std::string>();
            double price = std::stod(it.value()[1].get<std::string>());
            double size = std::stod(it.value()[2].get<std::string>());
            if (side == "buy") {
                m.lock();
                if (size == 0) {
                    b.bids.erase(price);
                } else {
                    b.bids[price] = size;
                }
                m.unlock();
            } else if (side == "sell") {
                m.lock();
                if (size == 0) {
                    b.asks.erase(price);
                } else {
                    b.asks[price] = size;
                }
                m.unlock();
            }
        }
    } else if (message["type"] == "heartbeat") {
        std::cout << "heartbeat" << std::endl;
    } else if (message["type"] == "subscriptions") {
        std::cout << "subscriptions" << std::endl;
    } else {
        std::cout << "unknown message type" << std::endl;
    }
}

context_ptr on_tls_init(client *c, websocketpp::connection_hdl hdl) {
    context_ptr ctx(new boost::asio::ssl::context(boost::asio::ssl::context::tlsv1));

    try {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                            boost::asio::ssl::context::no_sslv2 |
                            boost::asio::ssl::context::single_dh_use);
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    return ctx;
}

void *start_order_book(void *arg) {
    try {
        client c;
        std::string uri = "wss://ws-feed.exchange.coinbase.com:443";
        // Set logging to be pretty verbose (everything except message payloads)
        c.set_access_channels(websocketpp::log::alevel::all);
        c.clear_access_channels(websocketpp::log::alevel::frame_payload);

        c.init_asio();
        c.set_tls_init_handler(bind(&on_tls_init, &c, ::_1));
        c.set_open_handler(bind(&on_open, &c, ::_1));
        c.set_message_handler(bind(&on_message,&c, ::_1, ::_2));

        websocketpp::lib::error_code ec;
        client::connection_ptr con = c.get_connection(uri, ec);
        if (ec) {
            std::cout << "could not create connection because: " << ec.message() << std::endl;
            return NULL;
        }
        c.connect(con);
        c.run();
    } catch (websocketpp::exception const & e) {
        std::cout << "websocket error: " << e.what() << std::endl;
    } catch (json::type_error const & e) {
        std::cout << "json type error: " << e.what() << std::endl;
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc == 2) {
        product_id = argv[1];
    }

    pthread_t t1;
    int res = pthread_create(&t1, NULL, start_order_book, NULL);
    if (res) {
        std::cout << "error: " << res << std::endl; 
    }
    sleep(10);
}