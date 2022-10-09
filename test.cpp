#include <string>
#include <functional>
#include <iostream>
#include <mutex>
#include <cstring>
#include <thread>
#include <sstream>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <fnmatch.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

typedef std::unordered_map<std::string, std::string> headers;
typedef int socket_t;

struct addrinfo* resolve_dns(const std::string& hostname, int port, std::string& err_msg) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string sport = std::to_string(port);
    struct addrinfo* res;
    int getaddrinfo_result = getaddrinfo(hostname.c_str(), sport.c_str(), &hints, &res);
    if (getaddrinfo_result) {
        err_msg = gai_strerror(getaddrinfo_result);
        res = nullptr;
    }
    return res;
};

class SecureSocket {
public:
    SecureSocket(){
        openssl_initialize();
    }

    ~SecureSocket() {
        ssl_close();
    };

    bool ssl_connect(const std::string& host, int port, std::string& err_msg) {
        bool handshake_successful = false;
        {
            std::lock_guard<std::mutex> lock(_ssl_mutex);
            _sockfd = socket_connect(host, port, err_msg);
            if (_sockfd == -1) return false;
            _ssl_context = openssl_create_context(err_msg);
            if (_ssl_context == nullptr) {
                return false;
            }

            _ssl_connection = SSL_new(_ssl_context);
            if (_ssl_connection == nullptr) {
                err_msg = "OpenSSL failed to connect";
                SSL_CTX_free(_ssl_context);
                _ssl_context = nullptr;
                return false;
            }
            SSL_set_fd(_ssl_connection, _sockfd);

            SSL_set_tlsext_host_name(_ssl_connection, host.c_str());
            X509_VERIFY_PARAM* param = SSL_get0_param(_ssl_connection);
            X509_VERIFY_PARAM_set1_host(param, host.c_str(), host.size());
            handshake_successful = openssl_client_handshake(host, err_msg);
        }

        if (!handshake_successful) {
            ssl_close();
            return false;
        }

        return true;
    };

    void ssl_close() {
        std::lock_guard<std::mutex> lock(_ssl_mutex);
        if (_ssl_connection != nullptr) {
            SSL_free(_ssl_connection);
            _ssl_connection = nullptr;
        }
        if (_ssl_context != nullptr) {
            SSL_CTX_free(_ssl_context);
            _ssl_context = nullptr;
        }

        socket_close();
        std::cout << "closed ssl connection" << std::endl;
    };

    bool write_bytes(const std::string& str) {
        int offset = 0;
        ssize_t len = str.size();
        while (true) {
            ssize_t ret = send((char*) &str[offset], len);
            if (ret > 0){
                if (ret == len) {
                    return true;
                } else {
                    offset += ret;
                    len -= ret;
                    continue;
                }
            } else {
                return false;
            }
        }
    }

    ssize_t send(char* buf, size_t nbyte){
        std::lock_guard<std::mutex> lock(_ssl_mutex);
        if (_ssl_connection == nullptr || _ssl_context == nullptr) {
            return 0;
        }

        ERR_clear_error();
        ssize_t write_result = SSL_write(_ssl_connection, buf, (int) nbyte);
        int reason = SSL_get_error(_ssl_connection, (int) write_result);

        if (reason == SSL_ERROR_NONE) {
            return write_result;
        } else if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) {
            errno = EWOULDBLOCK;
            return -1;
        } else {
            return -1;
        }
    };

    bool read_byte(void* buffer) {
        while (true) {
            ssize_t ret = receive(buffer, 1);
            if (ret == 1) {
                return true;
            } else {
                return false;
            }
        }
    }

    std::pair<bool, std::string> read_line() {
        char c;
        std::string line;
        line.reserve(64);
        for (int i = 0; i < 2 || (line[i - 2] != '\r' && line[i - 1] != '\n'); ++i) {
            if (!read_byte(&c)) {
                return std::make_pair(false, line);
            }
            line += c;
        }
        return std::make_pair(true, line);
    }

    ssize_t receive(void* buf, size_t nbyte) {
        while (true) {
            std::lock_guard<std::mutex> lock(_ssl_mutex);
            if (_ssl_connection == nullptr || _ssl_context == nullptr) {
                return 0;
            }

            ERR_clear_error();
            ssize_t read_result = SSL_read(_ssl_connection, buf, (int) nbyte);
            if (read_result > 0) {
                return read_result;
            }

            int reason = SSL_get_error(_ssl_connection, (int) read_result);
            if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) {
                errno = EWOULDBLOCK;
            }
            return -1;
        }
    };

private:
    void socket_close() {
        std::lock_guard<std::mutex> lock(_socket_mutex);
        if (_sockfd == -1) return;
        ::close(_sockfd);
        _sockfd = -1;
    }

    int connect_to_address(const struct addrinfo* address, std::string& err_msg) {
        err_msg = "no error";
        socket_t fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) {
            err_msg = "Cannot create a socket";
            return -1;
        }

        int flag = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*) &flag, sizeof(flag));
        int res = ::connect(fd, address->ai_addr, address->ai_addrlen);
        if (res == -1) {
            err_msg = strerror(errno);
            ::close(fd);
            return -1;
        }

        return fd;
    }

    int socket_connect(const std::string& hostname, int port, std::string& err_msg) {
        std::string dns_err_msg;
        struct addrinfo* res = resolve_dns(hostname, port, dns_err_msg);
        if (res == nullptr) {
            return -1;
        }
        struct sockaddr_in* addr = (struct sockaddr_in *)res->ai_addr; 
        std::cout << "resolved IP address " << inet_ntoa((struct in_addr)addr->sin_addr) << std::endl;
        int sockfd = -1;
        struct addrinfo* address;
        for (address = res; address != nullptr; address = address->ai_next) {
            sockfd = connect_to_address(address, err_msg);
            if (sockfd != -1) {
                break;
            }
        }

        freeaddrinfo(res);
        return sockfd;
    }

    void openssl_initialize() {
        if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr)) {
            throw std::runtime_error("cannot initialize openssl");
        }
        (void) OpenSSL_add_ssl_algorithms();
        (void) SSL_load_error_strings();
        std::cout << "openssl initialized" << std::endl;
    };

    std::string get_ssl_error(int ret) {
        unsigned long e;
        int err = SSL_get_error(_ssl_connection, ret);
        if (err == SSL_ERROR_WANT_CONNECT || err == SSL_ERROR_WANT_ACCEPT) {
            return "openssl failed - connection failure";
        } else if (err == SSL_ERROR_WANT_X509_LOOKUP) {
            return "openssl failed - x509 error";
        } else if (err == SSL_ERROR_SYSCALL) {
            e = ERR_get_error();
            if (e > 0) {
                std::string err_msg("openssl failed - ");
                err_msg += ERR_error_string(e, nullptr);
                return err_msg;
            } else if (e == 0 && ret == 0) {
                return "openssl failed - received early EOF";
            } else {
                return "openssl failed - underlying BIO reported an I/O error";
            }
        } else if (err == SSL_ERROR_SSL) {
            e = ERR_get_error();
            std::string err_msg("openssl failed - ");
            err_msg += ERR_error_string(e, nullptr);
            return err_msg;
        } else if (err == SSL_ERROR_NONE) {
            return "openssl failed - err none";
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            return "openssl failed - err zero return";
        } else {
            return "openssl failed - unknown error";
        }
    };

    SSL_CTX* openssl_create_context(std::string& err_msg) {
        const SSL_METHOD* method = SSLv23_client_method();
        if (method == nullptr) {
            err_msg = "SSLv23_client_method failure";
            return nullptr;
        }
        _ssl_method = method;

        SSL_CTX* ctx = SSL_CTX_new(_ssl_method);
        if (ctx) {
            SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
            int options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_CIPHER_SERVER_PREFERENCE;
            options |= SSL_OP_NO_TLSv1_3;
            SSL_CTX_set_options(ctx, options);
        }
        return ctx;
    }

    bool openssl_client_handshake(const std::string& hostname, std::string& err_msg) {
        while (true) {
            if (_ssl_connection == nullptr || _ssl_context == nullptr) {
                return false;
            }

            ERR_clear_error();
            int connect_result = SSL_connect(_ssl_connection);
            if (connect_result == 1) {
                return openssl_check_server_cert(_ssl_connection, hostname, err_msg);
            }
            int reason = SSL_get_error(_ssl_connection, connect_result);
            bool rc = false;
            if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) {
                rc = true;
            } else {
                err_msg = get_ssl_error(connect_result);
                rc = false;
            }

            if (!rc) {
                return false;
            }
        }
    };
    bool openssl_check_server_cert(SSL* ssl, const std::string& hostname, std::string& err_msg) {
        X509* server_cert = SSL_get_peer_certificate(ssl);
        if (server_cert == nullptr) {
            err_msg = "openssl failed - server didn't present a X509 certificate.";
            return false;
        }
        
        char buf[256];
        X509_NAME_oneline(X509_get_subject_name(server_cert), buf, 256);
        std::cout << "openssl server cert subject: " << buf << std::endl;

        X509_free(server_cert);
        return true;
    };

    int _sockfd = -1;
    SSL* _ssl_connection = nullptr;
    SSL_CTX* _ssl_context = nullptr;
    const SSL_METHOD* _ssl_method;

    mutable std::mutex _ssl_mutex;
    std::mutex _socket_mutex;
};

enum class ReadyState {
    CLOSING,
    CLOSED,
    CONNECTING,
    OPEN
};

std::string trim(const std::string &s)
{
    auto start = s.begin();
    while (start != s.end() && std::isspace(*start)) {
        start++;
    }
 
    auto end = s.end();
    do {
        end--;
    } while (std::distance(start, end) > 0 && std::isspace(*end));
 
    return std::string(start, end + 1);
}

std::pair<std::string, int> parse_http_status(const std::string& line) {
    std::string token;
    std::stringstream ts(line);
    std::vector<std::string> tokens;
    while (std::getline(ts, token, ' ')) {
        tokens.push_back(token);
    }

    std::string http_version;
    if (tokens.size() >= 1){
        http_version = trim(tokens[0]);
    }

    int status_code = -1;
    if (tokens.size() >= 2) {
        std::stringstream ss;
        ss << trim(tokens[1]);
        ss >> status_code;
    }

    return std::make_pair(http_version, status_code);
}

std::pair<bool, headers> read_and_parse_headers(std::unique_ptr<SecureSocket>& socket) {
    headers headers;
    char line[1024];
    int i;
    while (true) {
        int colon = 0;
        for (i = 0; i < 2 || (i < 1023 && line[i - 2] != '\r' && line[i - 1] != '\n'); ++i) {
            if (!socket->read_byte(line + i)) {
                return std::make_pair(false, headers);
            }

            if (line[i] == ':' && colon == 0) {
                colon = i;
            }
        }
        if (line[0] == '\r' && line[1] == '\n'){
            break;
        }
        if (colon > 0) {
            line[i] = '\0';
            std::string line_str(line);
            int start = colon + 1;
            while (line_str[start] == ' ') {
                start++;
            }

            std::string name(line_str.substr(0, colon));
            for (auto& c : name) {
                c = std::tolower(c);
            }
            std::string value(line_str.substr(start, line_str.size() - start - 2));
            for (auto& c : value) {
                c = std::tolower(c);
            }
            headers[name] = value;
        }
    }

    return std::make_pair(true, headers);
}

class WebSocketClient final {
public:
    WebSocketClient(const std::string& url) :
    _url(url),
    _ready_state(ReadyState::CLOSED) {
    };
    ~WebSocketClient() {
    };
    void connect();
    void disconnect();
    void send(const std::string& message) {};
    void run() {
        // while (true)
        // {
        //     // 1. Make sure we are always connected
        //     checkConnection(firstConnectionAttempt);

        //     firstConnectionAttempt = false;

        //     // if here we are closed then checkConnection was not able to connect
        //     if (getReadyState() == ReadyState::Closed)
        //     {
        //         break;
        //     }

        //     // We can avoid to poll if we want to stop and are not closing
        //     if (_stop && !isClosing()) break;

        //     // 2. Poll to see if there's any new data available
        //     WebSocketTransport::PollResult pollResult = _ws.poll();

        //     // 3. Dispatch the incoming messages
        //     _ws.dispatch(
        //         pollResult,
        //         [this](const std::string& msg,
        //                size_t wireSize,
        //                bool decompressionError,
        //                WebSocketTransport::MessageKind messageKind) {
        //             WebSocketMessageType webSocketMessageType{WebSocketMessageType::Error};
        //             switch (messageKind)
        //             {
        //                 case WebSocketTransport::MessageKind::MSG_TEXT:
        //                 case WebSocketTransport::MessageKind::MSG_BINARY:
        //                 {
        //                     webSocketMessageType = WebSocketMessageType::Message;
        //                 }
        //                 break;

        //                 case WebSocketTransport::MessageKind::PING:
        //                 {
        //                     webSocketMessageType = WebSocketMessageType::Ping;
        //                 }
        //                 break;

        //                 case WebSocketTransport::MessageKind::PONG:
        //                 {
        //                     webSocketMessageType = WebSocketMessageType::Pong;
        //                 }
        //                 break;

        //                 case WebSocketTransport::MessageKind::FRAGMENT:
        //                 {
        //                     webSocketMessageType = WebSocketMessageType::Fragment;
        //                 }
        //                 break;
        //             }

        //             WebSocketErrorInfo webSocketErrorInfo;
        //             webSocketErrorInfo.decompressionError = decompressionError;

        //             bool binary = messageKind == WebSocketTransport::MessageKind::MSG_BINARY;

        //             _onMessageCallback(ix::make_unique<WebSocketMessage>(webSocketMessageType,
        //                                                                  msg,
        //                                                                  wireSize,
        //                                                                  webSocketErrorInfo,
        //                                                                  WebSocketOpenInfo(),
        //                                                                  WebSocketCloseInfo(),
        //                                                                  binary));

        //             WebSocket::invokeTrafficTrackerCallback(wireSize, true);
        //         });
        // }
    }
    void check_connection(bool first_connection_attempt)
    {
        // using millis = std::chrono::duration<double, std::milli>;

        // uint32_t retries = 0;
        // millis duration(0);

        // // Try to connect perpertually
        // while (true)
        // {
        //     if (isConnected() || isClosing() || _stop)
        //     {
        //         break;
        //     }

        //     if (!firstConnectionAttempt && !_automaticReconnection)
        //     {
        //         // Do not attempt to reconnect
        //         break;
        //     }

        //     firstConnectionAttempt = false;

        //     // Only sleep if we are retrying
        //     if (duration.count() > 0)
        //     {
        //         std::unique_lock<std::mutex> lock(_sleepMutex);
        //         _sleepCondition.wait_for(lock, duration);
        //     }

        //     if (_stop)
        //     {
        //         break;
        //     }

        //     // Try to connect synchronously
        //     ix::WebSocketInitResult status = connect(_handshakeTimeoutSecs);

        //     if (!status.success)
        //     {
        //         WebSocketErrorInfo connectErr;

        //         if (_automaticReconnection)
        //         {
        //             duration =
        //                 millis(calculateRetryWaitMilliseconds(retries++,
        //                                                       _maxWaitBetweenReconnectionRetries,
        //                                                       _minWaitBetweenReconnectionRetries));

        //             connectErr.wait_time = duration.count();
        //             connectErr.retries = retries;
        //         }

        //         connectErr.reason = status.errorStr;
        //         connectErr.http_status = status.http_status;

        //         _onMessageCallback(ix::make_unique<WebSocketMessage>(WebSocketMessageType::Error,
        //                                                              emptyMsg,
        //                                                              0,
        //                                                              connectErr,
        //                                                              WebSocketOpenInfo(),
        //                                                              WebSocketCloseInfo()));
        //     }
        // }
    };

    void start_websocket_connection(){
        std::string protocol, host;
        int port;
        std::string url(_url);
        parse_url(protocol, host, port, url);
        if (protocol != "wss") {
            throw std::runtime_error("invalid protocol: " + protocol);
        }
    
        std::string error_msg;
        _tls_socket = std::unique_ptr<SecureSocket>(new SecureSocket());
        bool success = _tls_socket->ssl_connect(host, port, error_msg);
        if (!success) {
            std::stringstream ss;
            ss << "unable to connect to " << host << " on port " << port << ", error: " << error_msg;
            throw std::runtime_error(ss.str());
        }

        std::cout << "ssl connect succeeded" << std::endl;

        std::stringstream ss;
        ss << "GET / HTTP/1.1\r\n";
        ss << "Host: " << host << ":" << port << "\r\n";
        ss << "Upgrade: websocket\r\n";
        ss << "Connection: Upgrade\r\n";
        ss << "Sec-WebSocket-Version: 13\r\n";
        ss << "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n";
        ss << "User-Agent: WeiWebSocket/1.0\r\n";
        ss << "\r\n";

        if (!_tls_socket->write_bytes(ss.str())) {
            throw std::runtime_error("failed sending GET request to " + url);
        }

        auto status_line = _tls_socket->read_line();
        bool line_valid = status_line.first;
        std::string line = status_line.second;

        if (!line_valid) {
            throw std::runtime_error("failed reading HTTP status line from " + url);
        }

        auto http_version_status = parse_http_status(line);
        std::string version = http_version_status.first;
        int status = http_version_status.second;

        if (version != "HTTP/1.1") {
            std::stringstream ss;
            ss << "http version is not 1.1 but " << version << ", status: " << status
               << ", http status line: " << line;
            throw std::runtime_error(ss.str());
        }

        auto result = read_and_parse_headers(_tls_socket);
        auto headers_valid = result.first;
        auto headers = result.second;

        if (!headers_valid){
            std::stringstream ss;
            throw std::runtime_error("failed parsing headers");
        }

        if (status != 101) {
            std::stringstream ss;
            ss << "status is not 101, got " << status
               << " status connecting to " << url << ", http status line: " << line;
            throw std::runtime_error(ss.str());
        }

        if (headers.find("connection") == headers.end())
        {
            throw std::runtime_error("no connection in header");
        }

        if (headers["connection"] != "upgrade") {
            std::stringstream ss;
            ss << "invalid connection value: " << headers["connection"];
            throw std::runtime_error(ss.str());
        }

        _ready_state = ReadyState::OPEN;
    };

    void set_on_message_callback(const std::function<void(const std::string&)>& callback);

    void parse_url(std::string& protocol, std::string& host, int& port, const std::string& url) {
        std::string::size_type pos = url.find("://");
        if (pos == std::string::npos) {
            throw std::runtime_error("invalid url");
        }
        protocol = url.substr(0, pos);
        std::string::size_type pos2 = url.find(":", pos + 3);
        if (pos2 == std::string::npos) {
            throw std::runtime_error("invalid url");
        }
        host = url.substr(pos + 3, pos2 - pos - 3);
        port = stoi(url.substr(pos2 + 1));
        std::cout << "protocol: " << protocol << std::endl;
        std::cout << "host: " << host << std::endl;
        std::cout << "port: " << port << std::endl;
    };
private:
    std::string _url;
    std::unique_ptr<SecureSocket> _tls_socket;
    ReadyState _ready_state;
};

int main() {
    WebSocketClient c("wss://ws-feed.exchange.coinbase.com:443");
    c.start_websocket_connection();
}
