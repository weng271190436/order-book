#include <string>
#include <functional>
#include <iostream>
#include <mutex>
#include <cstring>
#include <thread>
#include <sstream>
#include <unordered_map>
#include <vector>

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

const int HEADER_LINE_MAX = 1024;

struct addrinfo* resolve_dns(const std::string& hostname, int port, std::string& err_msg) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    // If hints.ai_flags includes the AI_ADDRCONFIG flag, then IPv4
    // addresses are returned in the list pointed to by res only if the
    // local system has at least one IPv4 address configured, and IPv6
    // addresses are returned only if the local system has at least one
    // IPv6 address configured.
    // If AI_NUMERICSERV is specified in hints.ai_flags and service is not
    // NULL, then service must point to a string containing a numeric
    // port number.
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;

    // AF_UNSPEC allows getaddrinfo() to return IPv4 and IPv6 addresses
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
        ssl_init();
    }

    ~SecureSocket() {
        ssl_close();
    };

    void wait() {
        // 100 milliseconds
        int timeout = 100;
        fd_set rfds;
        fd_set wfds;
        timeval tv = { timeout/1000, (timeout%1000) * 1000 };
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(_sockfd, &rfds);

        // wait for socket to become readable or timeout
        select(_sockfd + 1, &rfds, &wfds, 0, &tv);
    };

    bool ssl_connect(const std::string& host, int port, std::string& err_msg) {
        bool handshake_successful = false;
        {
            std::lock_guard<std::mutex> lock(_ssl_mutex);
            _sockfd = socket_connect(host, port, err_msg);
            if (_sockfd == -1) return false;
            _ssl_context = ssl_create_context(err_msg);
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

            // have to use Server Name Indication for handshake to work
            SSL_set_tlsext_host_name(_ssl_connection, host.c_str());
            X509_VERIFY_PARAM* param = SSL_get0_param(_ssl_connection);
            // X509_VERIFY_PARAM_set1_host() sets the expected DNS hostname to name clearing any previously specified host name or names
            X509_VERIFY_PARAM_set1_host(param, host.c_str(), host.size());
            handshake_successful = ssl_handshake(host, err_msg);
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

        // clear the error queue
        ERR_clear_error();

        // The write operation was successful, the return value is the number of bytes actually written to the TLS/SSL connection.
        ssize_t write_result = SSL_write(_ssl_connection, buf, (int) nbyte);
        int reason = SSL_get_error(_ssl_connection, (int) write_result);
        if (reason == SSL_ERROR_NONE) {
            return write_result;
        } else if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) {
            // this can happen when the send side buffer is full, which in turn means that your Server is not reading the messages sent from Client
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

    std::pair<bool, std::string> read_http_header_line() {
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
                // this can happen when the receive side buffer is empty, which in turn means that your Server is not sending any messages to Client
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
            err_msg = "cannot create a socket";
            return -1;
        }

        int flag = 1;

        // TCP_NODELAY disables Nagle's algorithm
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

    void ssl_init() {
        // With OPENSSL_INIT_LOAD_CONFIG an OpenSSL configuration file will be automatically loaded
        if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr)) {
            throw std::runtime_error("cannot initialize openssl");
        }
        // SSL_library_init() registers the available SSL/TLS ciphers and digests.
        SSL_library_init();
        (void) SSL_load_error_strings();
        std::cout << "openssl initialized" << std::endl;
    };

    std::string get_ssl_error(int ret) {
        unsigned long e;
        int err = SSL_get_error(_ssl_connection, ret);
        if (err == SSL_ERROR_WANT_CONNECT || err == SSL_ERROR_WANT_ACCEPT) {
            // The operation did not complete; the same TLS/SSL I/O function should be called again later.
            return "openssl failed - connection failure";
        } else if (err == SSL_ERROR_WANT_X509_LOOKUP) {
            // The operation did not complete because an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again.
            return "openssl failed - x509 error";
        } else if (err == SSL_ERROR_SYSCALL) {
            // Some non-recoverable, fatal I/O error occurred.
            // The OpenSSL error queue may contain more information on the error.
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

    // ssl_create_context creates a new SSL_CTX object
    SSL_CTX* ssl_create_context(std::string& err_msg) {
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
            SSL_CTX_set_options(ctx, options);
        }
        return ctx;
    }

    // ssl_handshake performs the SSL handshake with the server
    bool ssl_handshake(const std::string& hostname, std::string& err_msg) {
        while (true) {
            if (_ssl_connection == nullptr || _ssl_context == nullptr) {
                return false;
            }

            ERR_clear_error();
            int connect_result = SSL_connect(_ssl_connection);
            // connect_result = 0 means the handshake was not successful but was shut down controlled and by the specifications of the TLS/SSL protocol
            // connect_result = 1 means the handshake was successful
            // connect_result < 0 means the handshake was not successful, because a fatal error occurred either at the protocol level or a connection failure occurred.
            if (connect_result == 1) {
                return ssl_check_server_cert(_ssl_connection, hostname, err_msg);
            }
            int reason = SSL_get_error(_ssl_connection, connect_result);
            bool rc = false;
            // SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE are expected
            // for non-blocking sockets when SSL_connect() is called
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

    bool ssl_check_server_cert(SSL* ssl, const std::string& hostname, std::string& err_msg) {
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
    CLOSED,
    OPEN
};

struct WebSocketHeader {
    unsigned header_size;
    bool fin;
    bool rsv1;
    bool rsv2;
    bool rsv3;
    bool mask;
    enum OpcodeType {
        CONTINUATION = 0x0,
        TEXT_FRAME = 0x1,
        BINARY_FRAME = 0x2,
        // 0x3-0x7 are reserved for further non-control frames
        CLOSE = 0x8,
        PING = 0x9,
        PONG = 0xa,
        // 0xb-0xf are reserved for further control frames
    } opcode;
    int N0;
    uint64_t N;
    uint8_t masking_key[4];
};

struct WebSocketCloseCode {
    // 1000 indicates a normal closure, meaning that the purpose for
    // which the connection was established has been fulfilled.
    static const uint16_t NORMAL = 1000;
};

// trim removes leading and trailing whitespace from a string
std::string trim(const std::string &s) {
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

// parse_http_status parses the HTTP status line and returns the HTTP version and status code
// input similar to HTTP/1.1 101 Switching Protocols
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

// read_and_parse_headers tries to read the HTTP headers from the socket and returns
// whether the headers are valid and a map of header keys to values
// also convert the header keys and values to lowercase
// the headers look like this:
// Upgrade: websocket\r\n
// Connection: Upgrade\r\n
// Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n
// \r\n
std::pair<bool, headers> read_and_parse_headers(std::unique_ptr<SecureSocket>& socket) {
    headers headers;
    char line[HEADER_LINE_MAX];
    int i;
    while (true) {
        int colon = 0;

        // the last line is \r\n
        // the other lines are <key>: <value>\r\n
        for (i = 0; i < 2 || (i < HEADER_LINE_MAX-1 && line[i - 2] != '\r' && line[i - 1] != '\n'); ++i) {
            if (!socket->read_byte(line + i)) {
                return std::make_pair(false, headers);
            }

            // if we see a colon, note the position
            if (line[i] == ':' && colon == 0) {
                colon = i;
            }
        }
        // found the last line
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
            // -2 to remove the \r\n
            std::string value(line_str.substr(start, line_str.size() - start - 2));
            for (auto& c : value) {
                c = std::tolower(c);
            }
            headers[name] = value;
        }
    }

    return std::make_pair(true, headers);
}

// parse_url parses a URL such as wss://ws-feed.exchange.coinbase.com:443 into its components
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
        std::cout << "CoinbaseWebSocketClient destructor" << std::endl;
    };
    void send_text(const std::string& message) {
        send_message(WebSocketHeader::OpcodeType::TEXT_FRAME, message);
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
                    _tls_socket->ssl_close();
                    throw std::runtime_error("receive failed with return code" + std::to_string(ret));
                } else {
                    _receive_buffer.insert(_receive_buffer.end(), _readbuf.begin(), _readbuf.begin() + ret);
                }
            }
        }

        read_buffer();
    }

    void start_connection(){
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
        // TODO: generate random key
        ss << "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
        ss << "User-Agent: WeiWebSocket/1.0\r\n";
        ss << "\r\n";

        // TODO: implement subprotocols

        if (!_tls_socket->write_bytes(ss.str())) {
            throw std::runtime_error("failed sending GET request to " + url);
        }

        auto status_line = _tls_socket->read_http_header_line();
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

        // 101 means switching protocols
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

        // TODO: check Sec-WebSocket-Accept header

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

    // send_message sends a message with a opcode
    void send_message(WebSocketHeader::OpcodeType opcode, const std::string& message) {
        if (_ready_state != ReadyState::OPEN){
            throw std::runtime_error("web socket is not open, current state: " + std::to_string(static_cast<int>(_ready_state)));
        }
        auto message_begin = message.cbegin();
        auto message_end = message.cend();
        {
            std::lock_guard<std::mutex> lock(_send_buffer_mutex);
            _send_buffer.reserve(message.size());
        }

        uint64_t message_size = static_cast<uint64_t>(message_end - message_begin);
        // TODO: pick random mask key
        const uint8_t masking_key[4] = { 0x21, 0x43, 0x65, 0x87 };
        bool use_mask = true;
        std::vector<uint8_t> header;

        // assign header bytes
        // if the message size >= 126, assign 2 more bytes
        // if the message size >= 2^16, assign 8 more bytes
        // if masked, assign 4 more bytes
        header.assign(2 + (message_size >= 126 ? 2 : 0) + (message_size >= 65536 ? 6 : 0) +
                          (use_mask ? 4 : 0),
                      0);
        header[0] = opcode;

        // set fin bit
        // TODO: support fragmented message
        header[0] |= 0x80;

        if (message_size < 126) {
            // 2nd byte first bit is mask bit
            // the other bits are the message size (if message size < 126)
            header[1] = (message_size & 0xff) | (use_mask ? 0x80 : 0);
            if (use_mask) {
                // the following 4 bytes are the mask key
                header[2] = masking_key[0];
                header[3] = masking_key[1];
                header[4] = masking_key[2];
                header[5] = masking_key[3];
            }
        } else if (message_size < 65536) {
            // if the message size < 2^16, the 2nd byte is 126
            // set mask bit if needed
            header[1] = 126 | (use_mask ? 0x80 : 0);
            // the following 2 bytes are the message size
            header[2] = (message_size >> 8) & 0xff;
            header[3] = (message_size >> 0) & 0xff;
            if (use_mask) {
                // the following 4 bytes are the mask key
                header[4] = masking_key[0];
                header[5] = masking_key[1];
                header[6] = masking_key[2];
                header[7] = masking_key[3];
            }
        } else {
            // if the message size >= 2^16, the 2nd byte is 127
            // set mask bit if needed
            header[1] = 127 | (use_mask ? 0x80 : 0);

            // the following 8 bytes are the message size
            header[2] = (message_size >> 56) & 0xff;
            header[3] = (message_size >> 48) & 0xff;
            header[4] = (message_size >> 40) & 0xff;
            header[5] = (message_size >> 32) & 0xff;
            header[6] = (message_size >> 24) & 0xff;
            header[7] = (message_size >> 16) & 0xff;
            header[8] = (message_size >> 8) & 0xff;
            header[9] = (message_size >> 0) & 0xff;

            if (use_mask) {
                // the following 4 bytes are the mask key
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
                // mask payload
                // Octet i of the transformed data ("transformed-octet-i") is the XOR of
                // octet i of the original data ("original-octet-i") with octet at index
                // i modulo 4 of the masking key ("masking-key-octet-j"):
                // j = i MOD 4
                // transformed-octet-i = original-octet-i XOR masking-key-octet-j
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
                    _tls_socket->ssl_close();
                    _ready_state = ReadyState::CLOSED;
                } else {
                    _send_buffer.erase(_send_buffer.begin(), _send_buffer.begin() + ret);
                    std::cout << "sent " << ret << " bytes: " << message << std::endl;
                }
            }
        }
    }

    // read_buffer reads the receive buffer, parses websocket header, and process message
    void read_buffer() {
        while (true) {
            WebSocketHeader ws;

            // receive buffer doesn't have enough bytes
            if (_receive_buffer.size() < 2) return;
            const uint8_t* data = (uint8_t*) &_receive_buffer[0];

            // parse header defined in https://www.rfc-editor.org/rfc/rfc6455

            // 1st bit indicate final fragment
            ws.fin = (data[0] & 0x80) == 0x80;

            // 2nd, 3rd, 4th bits are reserved bits must be 0
            // MUST be 0 unless an extension is negotiated that defines meanings
            // for non-zero values.  If a nonzero value is received and none of
            // the negotiated extensions defines the meaning of such a nonzero
            // value, the receiving endpoint MUST _Fail the WebSocket
            // Connection_.
            ws.rsv1 = (data[0] & 0x40) == 0x40;
            ws.rsv2 = (data[0] & 0x20) == 0x20;
            ws.rsv3 = (data[0] & 0x10) == 0x10;

            // 5th, 6th, 7th, 8th bits are opcode
            ws.opcode = (WebSocketHeader::OpcodeType)(data[0] & 0x0f);

            // 9th bit indicates whether the data is masked
            ws.mask = (data[1] & 0x80) == 0x80;

            // 10th to 16th bits are payload length
            // If 0-125, that is the payload length.
            // If 126, the following 2 bytes interpreted as a 16-bit unsigned integer are the payload length.
            // If 127, the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant
            // bit MUST be 0) are the payload length.
            ws.N0 = (data[1] & 0x7f);            

            // if payload length is 126, read 2 more bytes
            // if payload length is 127, read 8 more bytes
            // if masked, read 4 more bytes
            ws.header_size = 2 + (ws.N0 == 126 ? 2 : 0) + (ws.N0 == 127 ? 8 : 0) + (ws.mask ? 4 : 0);
            if (_receive_buffer.size() < ws.header_size) {
                std::cout << "buffer size smaller than header size" << std::endl;
                return;
            }

            if (ws.rsv1 || ws.rsv2 || ws.rsv3) {
                throw std::runtime_error("reserved bits used");
            }

            int i = 0;
            if (ws.N0 < 126) {
                // ws.N0 is the payload length
                ws.N = ws.N0;
                // if masked, mask starts at 3rd byte
                i = 2;
            } else if (ws.N0 == 126) {
                // read 2 bytes as payload length
                ws.N = 0;
                ws.N |= ((uint64_t) data[2]) << 8;
                ws.N |= ((uint64_t) data[3]) << 0;
                // if masked, mask starts at 5th byte
                i = 4;
            } else if (ws.N0 == 127) {
                // read 8 bytes as payload length
                ws.N = 0;
                ws.N |= ((uint64_t) data[2]) << 56;
                ws.N |= ((uint64_t) data[3]) << 48;
                ws.N |= ((uint64_t) data[4]) << 40;
                ws.N |= ((uint64_t) data[5]) << 32;
                ws.N |= ((uint64_t) data[6]) << 24;
                ws.N |= ((uint64_t) data[7]) << 16;
                ws.N |= ((uint64_t) data[8]) << 8;
                ws.N |= ((uint64_t) data[9]) << 0;
                // if masked, mask starts at 11th byte
                i = 10;
            } else {
                throw std::runtime_error("invalid payload length");
            }

            if (ws.mask) {
                // if masked, read 4 bytes as mask
                ws.masking_key[0] = (uint8_t) data[i + 0];
                ws.masking_key[1] = (uint8_t) data[i + 1];
                ws.masking_key[2] = (uint8_t) data[i + 2];
                ws.masking_key[3] = (uint8_t) data[i + 3];
            } else {
                ws.masking_key[0] = 0;
                ws.masking_key[1] = 0;
                ws.masking_key[2] = 0;
                ws.masking_key[3] = 0;
            }

            // if receive buffer doesn't have enough bytes, return so we can read more
            if (_receive_buffer.size() < ws.header_size + ws.N) {
                return;
            }

            // unmask payload
            // Octet i of the transformed data ("transformed-octet-i") is the XOR of
            // octet i of the original data ("original-octet-i") with octet at index
            // i modulo 4 of the masking key ("masking-key-octet-j"):
            // j = i MOD 4
            // transformed-octet-i = original-octet-i XOR masking-key-octet-j
            if (ws.mask) {
                for (size_t j = 0; j != ws.N; ++j) {
                    _receive_buffer[j + ws.header_size] ^= ws.masking_key[j & 0x3];
                }
            }

            // TODO: have not yet verified BINARY_FRAME and CONTINUATION_FRAME handling works against real websocket servers
            if (ws.opcode == WebSocketHeader::TEXT_FRAME || ws.opcode == WebSocketHeader::BINARY_FRAME || ws.opcode == WebSocketHeader::CONTINUATION) {
                _chunks.insert(_chunks.end(), _receive_buffer.begin()+ws.header_size, _receive_buffer.begin()+ws.header_size+(size_t)ws.N);
                if (ws.fin) {
                    // if this is the final frame, call the message handler and removed stored chunks
                    std::string full_message = std::string(_chunks.begin(), _chunks.end());
                    _on_message_callback(full_message);
                    _chunks.erase(_chunks.begin(), _chunks.end());

                    // free _chunks memory
                    std::vector<uint8_t> ().swap(_chunks);
                }
            }

            // TODO: implement PING, PONG, CLOSE

            // clear the received buffer after saving the message in _chunks or calling the message handler
            _receive_buffer.erase(_receive_buffer.begin(), _receive_buffer.begin() + ws.header_size+(size_t)ws.N);
        }
    }
};
