#include <string>
#include <functional>
#include <iostream>
#include <mutex>
#include <cstring>
#include <thread>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <fnmatch.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

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
    SecureSocket(int fd = -1)
        : _sockfd(fd)
        , _ssl_connection(nullptr)
        , _ssl_context(nullptr) {
        std::call_once(_openssl_init_flag, &SecureSocket::openssl_initialize, this);
    }

    ~SecureSocket() {
        ssl_close();
    };

    bool init(std::string& errorMsg) {
        return true;
    };

    bool ssl_connect(const std::string& host, int port, std::string& err_msg) {
        bool handshake_successful = false;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            if (!_openssl_initialization_successful) {
                err_msg = "OPENSSL_init_ssl failure";
                return false;
            }

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
        std::lock_guard<std::mutex> lock(_mutex);
        if (_ssl_connection != nullptr) {
            SSL_free(_ssl_connection);
            _ssl_connection = nullptr;
        }
        if (_ssl_context != nullptr) {
            SSL_CTX_free(_ssl_context);
            _ssl_context = nullptr;
        }

        socket_close();
    };

    ssize_t send(char* buf, size_t nbyte){
        std::lock_guard<std::mutex> lock(_mutex);
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
    ssize_t receive(void* buf, size_t nbyte) {
        while (true)
        {
            std::lock_guard<std::mutex> lock(_mutex);
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
        if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr)) return;

        (void) OpenSSL_add_ssl_algorithms();
        (void) SSL_load_error_strings();

        _openssl_initialization_successful = true;
    };
    std::string get_ssl_error(int ret) {
        unsigned long e;
        int err = SSL_get_error(_ssl_connection, ret);
        if (err == SSL_ERROR_WANT_CONNECT || err == SSL_ERROR_WANT_ACCEPT) {
            return "OpenSSL failed - connection failure";
        } else if (err == SSL_ERROR_WANT_X509_LOOKUP) {
            return "OpenSSL failed - x509 error";
        } else if (err == SSL_ERROR_SYSCALL) {
            e = ERR_get_error();
            if (e > 0) {
                std::string err_msg("OpenSSL failed - ");
                err_msg += ERR_error_string(e, nullptr);
                return err_msg;
            } else if (e == 0 && ret == 0) {
                return "OpenSSL failed - received early EOF";
            } else {
                return "OpenSSL failed - underlying BIO reported an I/O error";
            }
        } else if (err == SSL_ERROR_SSL) {
            e = ERR_get_error();
            std::string err_msg("OpenSSL failed - ");
            err_msg += ERR_error_string(e, nullptr);
            return err_msg;
        } else if (err == SSL_ERROR_NONE) {
            return "OpenSSL failed - err none";
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            return "OpenSSL failed - err zero return";
        } else {
            return "OpenSSL failed - unknown error";
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
            err_msg = "OpenSSL failed - peer didn't present a X509 certificate.";
            return false;
        }

        X509_free(server_cert);
        return true;
    };

    int _sockfd;
    SSL* _ssl_connection;
    SSL_CTX* _ssl_context;
    const SSL_METHOD* _ssl_method;

    mutable std::mutex _mutex;
    std::mutex _socket_mutex;

    static std::once_flag _openssl_init_flag;
    static std::atomic<bool> _openssl_initialization_successful;
};

std::once_flag SecureSocket::_openssl_init_flag;
std::atomic<bool> SecureSocket::_openssl_initialization_successful(false);

class WebSocketClient final {
public:
    WebSocketClient() {
    };
    ~WebSocketClient() {
    };
    void connect();
    void disconnect();
    void set_url(const std::string& url) { m_url = url; };
    void send(const std::string& message);
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

    void connect_to_url(const std::string& url, const headers& h, int timeout_secs){
        std::string protocol, host;
        int port;
        std::string url_copy(url);
        parse_url(protocol, host, port, url_copy);
        if (protocol != "wss") {
            throw std::runtime_error("Invalid protocol: " + protocol);
        }
    
        const int max_redirections = 10;
        for (int i = 0; i < max_redirections; ++i) {
            std::string error_msg;
            _tls_socket = std::unique_ptr<SecureSocket>(new SecureSocket(-1));
            if (!_tls_socket->init(error_msg)) {
                _tls_socket.reset();
            }
            // _perMessageDeflate = ix::make_unique<WebSocketPerMessageDeflate>();

    //         if (!_socket)
    //         {
    //             return WebSocketInitResult(false, 0, errorMsg);
    //         }

    //         WebSocketHandshake webSocketHandshake(_requestInitCancellation,
    //                                               _socket,
    //                                               _perMessageDeflate,
    //                                               _perMessageDeflateOptions,
    //                                               _enablePerMessageDeflate);

    //         result = webSocketHandshake.clientHandshake(
    //             remoteUrl, headers, host, path, port, timeoutSecs);

    //         if (result.http_status >= 300 && result.http_status < 400)
    //         {
    //             auto it = result.headers.find("Location");
    //             if (it == result.headers.end())
    //             {
    //                 std::stringstream ss;
    //                 ss << "Missing Location Header for HTTP Redirect response. "
    //                    << "Rejecting connection to " << url << ", status: " << result.http_status;
    //                 result.errorStr = ss.str();
    //                 break;
    //             }

    //             remoteUrl = it->second;
    //             continue;
    //         }

    //         if (result.success)
    //         {
    //             setReadyState(ReadyState::OPEN);
    //         }
    //         return result;
        }

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
    std::string m_url;
    std::unique_ptr<SecureSocket> _tls_socket;
};

int main() {
    WebSocketClient c;
    std::string url("wss://ws-feed.exchange.coinbase.com:443");
    c.set_url(url);
    std::string protocol, host;
    int port;
    c.parse_url(protocol, host, port, url);

    std::string dns_err_msg;
    struct addrinfo* address_info = resolve_dns(host, port, dns_err_msg);
    struct sockaddr_in* addr = (struct sockaddr_in *)address_info->ai_addr; 
    std::cout << "IP address: " << inet_ntoa((struct in_addr)addr->sin_addr) << std::endl;

    SecureSocket s(-1);
    std::string socket_err_msg;
    bool ssl_connect_success = s.ssl_connect(host, port, socket_err_msg);
    std::cout << "ssl connect success: " << std::boolalpha << ssl_connect_success << std::endl;
    std::cout << "socket err msg: " << socket_err_msg << std::endl;

    c.connect_to_url(url, headers(), 10);
}