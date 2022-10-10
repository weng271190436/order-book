#include <string>
#include <functional>
#include <iostream>
#include <mutex>
#include <cstring>
#include <thread>
#include <sstream>
#include <list>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <fnmatch.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>

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

    void wait() {
        int timeout = 100;
        fd_set rfds;
        fd_set wfds;
        timeval tv = { timeout/1000, (timeout%1000) * 1000 };
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(_sockfd, &rfds);
        select(_sockfd + 1, &rfds, &wfds, 0, &tv);
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

    void set_socket_non_blocking() {
        fcntl(_sockfd, F_SETFL, O_NONBLOCK);
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
        std::cout << "resolved ip address " << inet_ntoa((struct in_addr)addr->sin_addr) << std::endl;
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

struct WebSocketHeader {
    unsigned header_size;
    bool fin;
    bool rsv1;
    bool rsv2;
    bool rsv3;
    bool mask;
    enum OpcodeType
    {
        CONTINUATION = 0x0,
        TEXT_FRAME = 0x1,
        BINARY_FRAME = 0x2,
        CLOSE = 8,
        PING = 9,
        PONG = 0xa,
    } opcode;
    int N0;
    uint64_t N;
    uint8_t masking_key[4];
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

class CoinbaseWebSocketClient final {
public:
    CoinbaseWebSocketClient(const std::string& url) :
    _url(url),
    _ready_state(ReadyState::CLOSED){
        _readbuf.resize(32 * 1024);
    };
    ~CoinbaseWebSocketClient() {
    };
    void send_text(const std::string& message) {
        if (_ready_state != ReadyState::OPEN && _ready_state != ReadyState::CLOSING){
            throw std::runtime_error("web socket is not open or closing, current state: " + std::to_string(static_cast<int>(_ready_state)));
        }
        auto message_begin = message.cbegin();
        auto message_end = message.cend();
        {
            std::lock_guard<std::mutex> lock(_send_buffer_mutex);
            _send_buffer.reserve(message.size());
        }

        uint64_t message_size = static_cast<uint64_t>(message_end - message_begin);
        const uint8_t masking_key[4] = { 0x12, 0x34, 0x56, 0x78 };
        bool use_mask = true;
        std::vector<uint8_t> header;
        header.assign(2 + (message_size >= 126 ? 2 : 0) + (message_size >= 65536 ? 6 : 0) +
                          (use_mask ? 4 : 0),
                      0);
        header[0] = WebSocketHeader::OpcodeType::TEXT_FRAME;
        header[0] |= 0x80;

        if (message_size < 126) {
            header[1] = (message_size & 0xff) | (use_mask ? 0x80 : 0);
            if (use_mask) {
                header[2] = masking_key[0];
                header[3] = masking_key[1];
                header[4] = masking_key[2];
                header[5] = masking_key[3];
            }
        } else if (message_size < 65536) {
            header[1] = 126 | (use_mask ? 0x80 : 0);
            header[2] = (message_size >> 8) & 0xff;
            header[3] = (message_size >> 0) & 0xff;
            if (use_mask) {
                header[4] = masking_key[0];
                header[5] = masking_key[1];
                header[6] = masking_key[2];
                header[7] = masking_key[3];
            }
        } else {
            header[1] = 127 | (use_mask ? 0x80 : 0);
            header[2] = (message_size >> 56) & 0xff;
            header[3] = (message_size >> 48) & 0xff;
            header[4] = (message_size >> 40) & 0xff;
            header[5] = (message_size >> 32) & 0xff;
            header[6] = (message_size >> 24) & 0xff;
            header[7] = (message_size >> 16) & 0xff;
            header[8] = (message_size >> 8) & 0xff;
            header[9] = (message_size >> 0) & 0xff;

            if (use_mask) {
                header[10] = masking_key[0];
                header[11] = masking_key[1];
                header[12] = masking_key[2];
                header[13] = masking_key[3];
            }
        }

        {
            std::lock_guard<std::mutex> lock(_send_buffer_mutex);
            _send_buffer.insert(_send_buffer.end(), header.begin(), header.end());
            _send_buffer.insert(_send_buffer.end(), message_begin, message_end);
            if (use_mask) {
                for (size_t i = 0; i != (size_t) message_size; ++i) {
                    *(_send_buffer.end() - (size_t) message_size + i) ^= masking_key[i & 0x3];
                }
            }

            while (_send_buffer.size()) {
                ssize_t ret = 0;
                {
                    std::lock_guard<std::mutex> lock(_socket_mutex);
                    ret = _tls_socket->send((char*) &_send_buffer[0], _send_buffer.size());
                }
                if (ret < 0){
                    throw std::runtime_error("send failed with return code" + std::to_string(ret));
                } else if (ret <= 0) {
                    close_socket();
                    _ready_state = ReadyState::CLOSED;
                } else {
                    _send_buffer.erase(_send_buffer.begin(), _send_buffer.begin() + ret);
                    std::cout << "sent " << ret << " bytes: " << message << std::endl;
                }
            }
        }
    };

    void poll() {
        _tls_socket->wait();
        {
            std::lock_guard<std::mutex> lock(_receive_buffer_mutex);
            while (true) {
                ssize_t ret = _tls_socket->receive((char*) &_readbuf[0], _readbuf.size());
                if (ret < 0) {
                    break;
                } else if (ret <= 0) {
                    close_socket();
                    throw std::runtime_error("receive failed with return code" + std::to_string(ret));
                } else {
                    _receive_buffer.insert(_receive_buffer.end(), _readbuf.begin(), _readbuf.begin() + ret);
                }
            }
        }

        read_buffer();
    }

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

        std::cout << "version: " << version << ", status: " << status << std::endl;

        if (version != "HTTP/1.1") {
            std::stringstream ss;
            ss << "http version is not 1.1 but " << version << ", status: " << status
               << ", http status line: " << line;
            throw std::runtime_error(ss.str());
        }

        auto result = read_and_parse_headers(_tls_socket);
        auto headers_valid = result.first;
        auto headers = result.second;

        for (auto& header : headers) {
            std::cout << header.first << ": " << header.second << std::endl;
        }

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
        _tls_socket->set_socket_non_blocking();
    };

    void set_on_message_callback(const std::function<void(const std::string&)> callback) {
        _on_message_callback = callback;
    };
private:
    std::function<void(const std::string&)> _on_message_callback;    

    std::string _url;
    std::unique_ptr<SecureSocket> _tls_socket;
    mutable std::mutex _socket_mutex;
    ReadyState _ready_state;

    std::vector<uint8_t> _send_buffer;
    mutable std::mutex _send_buffer_mutex;

    std::vector<uint8_t> _receive_buffer;
    mutable std::mutex _receive_buffer_mutex;

    std::vector<uint8_t> _readbuf;

    // hold fragmented message
    std::vector<uint8_t> _chunks;

    void close_socket() {
        std::lock_guard<std::mutex> lock(_socket_mutex);
        _tls_socket->ssl_close();
    }

    void read_buffer() {
        while (true) {
            WebSocketHeader ws;
            if (_receive_buffer.size() < 2) return;
            const uint8_t* data = (uint8_t*) &_receive_buffer[0];
            ws.fin = (data[0] & 0x80) == 0x80;
            ws.rsv1 = (data[0] & 0x40) == 0x40;
            ws.rsv2 = (data[0] & 0x20) == 0x20;
            ws.rsv3 = (data[0] & 0x10) == 0x10;
            ws.opcode = (WebSocketHeader::OpcodeType)(data[0] & 0x0f);
            ws.mask = (data[1] & 0x80) == 0x80;
            ws.N0 = (data[1] & 0x7f);
            ws.header_size =
                2 + (ws.N0 == 126 ? 2 : 0) + (ws.N0 == 127 ? 8 : 0) + (ws.mask ? 4 : 0);
            if (_receive_buffer.size() < ws.header_size) {
                std::cout << "buffer size smaller than header size" << std::endl;
                return;
            }

            if (ws.rsv1 || ws.rsv2 || ws.rsv3) {
                throw std::runtime_error("reserved bits used");
            }

            int i = 0;
            if (ws.N0 < 126) {
                ws.N = ws.N0;
                i = 2;
            } else if (ws.N0 == 126) {
                ws.N = 0;
                ws.N |= ((uint64_t) data[2]) << 8;
                ws.N |= ((uint64_t) data[3]) << 0;
                i = 4;
            } else if (ws.N0 == 127) {
                ws.N = 0;
                ws.N |= ((uint64_t) data[2]) << 56;
                ws.N |= ((uint64_t) data[3]) << 48;
                ws.N |= ((uint64_t) data[4]) << 40;
                ws.N |= ((uint64_t) data[5]) << 32;
                ws.N |= ((uint64_t) data[6]) << 24;
                ws.N |= ((uint64_t) data[7]) << 16;
                ws.N |= ((uint64_t) data[8]) << 8;
                ws.N |= ((uint64_t) data[9]) << 0;
                i = 10;
            } else {
                throw std::runtime_error("invalid payload length");
            }

            if (ws.mask) {
                ws.masking_key[0] = ((uint8_t) data[i + 0]) << 0;
                ws.masking_key[1] = ((uint8_t) data[i + 1]) << 0;
                ws.masking_key[2] = ((uint8_t) data[i + 2]) << 0;
                ws.masking_key[3] = ((uint8_t) data[i + 3]) << 0;
            } else {
                ws.masking_key[0] = 0;
                ws.masking_key[1] = 0;
                ws.masking_key[2] = 0;
                ws.masking_key[3] = 0;
            }

            const uint64_t max_frame_size(1ULL << 63);
            if (ws.N > max_frame_size) {
                throw std::runtime_error("frame too large");
            }

            if (_receive_buffer.size() < ws.header_size + ws.N) {
                return;
            }

            if (ws.mask) {
                for (size_t j = 0; j != ws.N; ++j) {
                    _receive_buffer[j + ws.header_size] ^= ws.masking_key[j & 0x3];
                }
            }

            if (ws.opcode == WebSocketHeader::TEXT_FRAME || ws.opcode == WebSocketHeader::BINARY_FRAME || ws.opcode == WebSocketHeader::CONTINUATION) {
                _chunks.insert(_chunks.end(), _receive_buffer.begin()+ws.header_size, _receive_buffer.begin()+ws.header_size+(size_t)ws.N);
                if (ws.fin) {
                    std::string full_message = std::string(_chunks.begin(), _chunks.end());
                    _on_message_callback(full_message);
                    _chunks.erase(_chunks.begin(), _chunks.end());
                    std::vector<uint8_t> ().swap(_chunks);
                }
            }

            _receive_buffer.erase(_receive_buffer.begin(), _receive_buffer.begin() + ws.header_size+(size_t)ws.N);
        }
    }
};
