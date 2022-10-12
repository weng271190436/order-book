#include "coinbase_client.hpp"

#include <nlohmann/json.hpp>
#include <httpserver.hpp>

#include <set>
#include <shared_mutex>
#include <csignal>
#include <future>

using json = nlohmann::json;

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
bool is_running = true;
std::shared_mutex is_running_mutex;

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

void *start_order_book(void *arg) {
    CoinbaseWebSocketClient c("wss://ws-feed.exchange.coinbase.com:443");
    c.set_on_message_callback([](const std::string& msg) {
        json message = json::parse(msg);
        if (message["type"] == "snapshot") {
            for (auto it = message["bids"].begin(); it != message["bids"].end(); ++it) {
                std::lock_guard<std::mutex> lock(bid_mutex);
                b.bids[std::stod(it.value()[0].get<std::string>())] = std::stod(it.value()[1].get<std::string>());
            }
            for (auto it = message["asks"].begin(); it != message["asks"].end(); ++it) {
                std::lock_guard<std::mutex> lock(ask_mutex);
                b.asks[std::stod(it.value()[0].get<std::string>())] = std::stod(it.value()[1].get<std::string>());
            }
        } else if (message["type"] == "l2update") {
            for (auto it = message["changes"].begin(); it != message["changes"].end(); ++it) {
                std::string side = it.value()[0].get<std::string>();
                double price = std::stod(it.value()[1].get<std::string>());
                double size = std::stod(it.value()[2].get<std::string>());
                if (side == "buy") {
                    std::lock_guard<std::mutex> lock(bid_mutex);
                    if (size == 0) {
                        b.bids.erase(price);
                    } else {
                        b.bids[price] = size;
                    }
                } else if (side == "sell") {
                    std::lock_guard<std::mutex> lock(ask_mutex);
                    if (size == 0) {
                        b.asks.erase(price);
                    } else {
                        b.asks[price] = size;
                    }
                }
            }
        } else if (message["type"] == "heartbeat") {
            print_yellow_line("heartbeat " + message["time"].get<std::string>());
        } else if (message["type"] == "subscriptions") {
            print_yellow_line("subscriptions");
        } else {
            print_yellow_line("unknown message type");
        }
    });
    c.start_connection();
    std::ostringstream ss;
    ss << "{ \"type\": \"subscribe\", \"channels\": [ { \"name\": \"heartbeat\", \"product_ids\": [ \"" << product_id << "\" ] }, { \"name\": \"level2\", \"product_ids\": [ \"" << product_id << "\" ] } ] }";
    std::string msg = ss.str();
    c.send_text(msg);
    while (true) {
        {
            std::shared_lock<std::shared_mutex> lock(is_running_mutex);
            if (!is_running) {
                break;
            }
        }
        c.poll();
    }
    return NULL;
}

void display_order_book() {
    int display_num = MAX_DISPLAY_NUM;
    print_green_line(product_id + " bids");
    {
        std::lock_guard<std::mutex> lock(bid_mutex);
        for (auto it = b.bids.begin(); it != b.bids.end(); ++it) {
            if (display_num-- == 0) {
                break;
            }
            print_green_line(double_to_string(it->first) + " " + double_to_string(it->second));
        }
    }
    display_num = MAX_DISPLAY_NUM;
    print_red_line(product_id + " asks");
    {
        std::lock_guard<std::mutex> lock(ask_mutex);
        for (auto it = b.asks.begin(); it != b.asks.end(); ++it) {
            if (display_num-- == 0) {
                break;
            }
            print_red_line(double_to_string(it->first) + " " + double_to_string(it->second));
        }
    }
}

std::string get_order_book_string() {
    std::string s;
    std::stringstream sstream;
    int display_num = MAX_DISPLAY_NUM;
    sstream << product_id << " bids\n--------------------" << std::endl;
    {
        std::lock_guard<std::mutex> lock(bid_mutex);
        for (auto it = b.bids.begin(); it != b.bids.end(); ++it) {
            if (display_num-- == 0) {
                break;
            }
            sstream << double_to_string(it->first) << " " << double_to_string(it->second) << std::endl;
        }
    }
    sstream << std::endl;
    display_num = MAX_DISPLAY_NUM;
    sstream << product_id << " asks\n--------------------" << std::endl;
    {
        std::lock_guard<std::mutex> lock(ask_mutex);
        for (auto it = b.asks.begin(); it != b.asks.end(); ++it) {
            if (display_num-- == 0) {
                break;
            }
            sstream << double_to_string(it->first) << " " << double_to_string(it->second) << std::endl;
        }
    }
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
    ws.start(false);
    while (true) {
        {
            std::shared_lock<std::shared_mutex> lock(is_running_mutex);
            if (!is_running) {
                std::cout << "stopping http server" << std::endl;
                ws.stop();
                break;
            }
        }
        sleep(0.1);
    }
    return NULL;
}

void *display_book(void *arg) {
    while (true) {
        {
            std::shared_lock<std::shared_mutex> lock(is_running_mutex);
            if (!is_running) {
                std::cout << "stopping display order book" << std::endl;
                break;
            }
        }
        sleep(1);
        display_order_book();
    }
    return NULL;
}

void signal_handler(int signum) {
    std::cout << "Interrupt signal (" << signum << ") received." << std::endl;
    {
        std::lock_guard<std::shared_mutex> lock(is_running_mutex);
        is_running = false;
    }
    sleep(1.1);
    exit(signum);  
}

int main(int argc, char* argv[]) {
    if (argc == 2) {
        product_id = argv[1];
    }

    signal(SIGINT, signal_handler);

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

    pthread_t t_display_book;
    res = pthread_create(&t_display_book, NULL, display_book, NULL);
    if (res) {
        std::cout << "thread display book error: " << res << std::endl; 
    }

    std::promise<void>().get_future().wait();
}
