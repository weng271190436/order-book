#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>
#include <nlohmann/json.hpp>
#include <httpserver.hpp>

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

const int MAX_DISPLAY_NUM = 10;
const int DOUBLE_DISPLAY_PRECISION = 10;

struct order_book {
    std::map<double, double, std::greater<double>> bids;
    std::map<double, double> asks;
};

order_book b;
std::string product_id = "BTC-USD";
std::mutex bid_mutex;
std::mutex ask_mutex;

std::string double_to_string(double d) {
    std::string s;
    std::stringstream sstream;
    sstream.setf(std::ios::fixed);
    sstream.precision(DOUBLE_DISPLAY_PRECISION);
    sstream << d;
    s = sstream.str();
    return s;
}

void print_green_line(std::string text) {
    std::cout << "\033[32m" << text << "\033[0m" << std::endl;
}

void print_red_line(std::string text) {
    std::cout << "\033[31m" << text << "\033[0m" << std::endl;
}

void print_yellow_line(std::string text) {
    std::cout << "\033[33m" << text << "\033[0m" << std::endl;
}

void on_open(client* c, websocketpp::connection_hdl hdl) {
    print_yellow_line("on open");
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
    json message = json::parse(msg->get_payload());
    if (message["type"] == "snapshot") {
        for (auto it = message["bids"].begin(); it != message["bids"].end(); ++it) {
            bid_mutex.lock();
            b.bids[std::stod(it.value()[0].get<std::string>())] = std::stod(it.value()[1].get<std::string>());
            bid_mutex.unlock();
        }
        for (auto it = message["asks"].begin(); it != message["asks"].end(); ++it) {
            ask_mutex.lock();
            b.asks[std::stod(it.value()[0].get<std::string>())] = std::stod(it.value()[1].get<std::string>());
            ask_mutex.unlock();
        }
    } else if (message["type"] == "l2update") {
        for (auto it = message["changes"].begin(); it != message["changes"].end(); ++it) {
            std::string side = it.value()[0].get<std::string>();
            double price = std::stod(it.value()[1].get<std::string>());
            double size = std::stod(it.value()[2].get<std::string>());
            if (side == "buy") {
                bid_mutex.lock();
                if (size == 0) {
                    b.bids.erase(price);
                } else {
                    b.bids[price] = size;
                }
                bid_mutex.unlock();
            } else if (side == "sell") {
                ask_mutex.lock();
                if (size == 0) {
                    b.asks.erase(price);
                } else {
                    b.asks[price] = size;
                }
                ask_mutex.unlock();
            }
        }
    } else if (message["type"] == "heartbeat") {
        print_yellow_line("heartbeat");
    } else if (message["type"] == "subscriptions") {
        print_yellow_line("subscriptions");
    } else {
        print_yellow_line("unknown message type");
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

void display_order_book() {
    int display_num = MAX_DISPLAY_NUM;
    print_green_line(product_id + " bids");
    bid_mutex.lock();
    for (auto it = b.bids.begin(); it != b.bids.end(); ++it) {
        if (display_num-- == 0) {
            break;
        }
        print_green_line(double_to_string(it->first) + " " + double_to_string(it->second));
    }
    bid_mutex.unlock();
    display_num = MAX_DISPLAY_NUM;
    print_red_line(product_id + " asks");
    ask_mutex.lock();
    for (auto it = b.asks.begin(); it != b.asks.end(); ++it) {
        if (display_num-- == 0) {
            break;
        }
        print_red_line(double_to_string(it->first) + " " + double_to_string(it->second));
    }
    ask_mutex.unlock();
}

std::string get_order_book_string() {
    std::string s;
    std::stringstream sstream;
    int display_num = MAX_DISPLAY_NUM;
    sstream << product_id << " bids\n--------------------" << std::endl;
    bid_mutex.lock();
    for (auto it = b.bids.begin(); it != b.bids.end(); ++it) {
        if (display_num-- == 0) {
            break;
        }
        sstream << double_to_string(it->first) << " " << double_to_string(it->second) << std::endl;
    }
    bid_mutex.unlock();
    sstream << std::endl;
    display_num = MAX_DISPLAY_NUM;
    sstream << product_id << " asks\n--------------------" << std::endl;
    ask_mutex.lock();
    for (auto it = b.asks.begin(); it != b.asks.end(); ++it) {
        if (display_num-- == 0) {
            break;
        }
        sstream << double_to_string(it->first) << " " << double_to_string(it->second) << std::endl;
    }
    ask_mutex.unlock();
    sstream << std::endl;
    s = sstream.str();
    return s;
}

class order_book_resource : public httpserver::http_resource {
public:
    std::shared_ptr<httpserver::http_response> render(const httpserver::http_request&) {
        return std::shared_ptr<httpserver::http_response>(new httpserver::string_response(get_order_book_string()));
    }
};

void *start_http_server(void *arg) {
    httpserver::webserver ws = httpserver::create_webserver(8080);
    order_book_resource obr;
    ws.register_resource("/orderbook", &obr);
    ws.start(true);
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc == 2) {
        product_id = argv[1];
    }

    pthread_t t_order_book;
    int res = pthread_create(&t_order_book, NULL, start_order_book, NULL);
    if (res) {
        std::cout << "thread order book error: " << res << std::endl; 
    }

    pthread_t t_http_server;
    res = pthread_create(&t_http_server, NULL, start_http_server, NULL);
    if (res) {
        std::cout << "thread http server error: " << res << std::endl; 
    }

    while (true) {
        sleep(1);
        display_order_book();
    }
}
