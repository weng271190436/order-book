#include <string>
#include <functional>
#include <unordered_map>
#include <stdexcept>
#include <iostream>
#include <memory>
#include <mutex>
#include <atomic>
#include <cstring>
#include <thread>
#include <fstream>
#include <sstream>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <fnmatch.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <assert.h>
#include <poll.h>
#include <arpa/inet.h>

typedef std::unordered_map<std::string, std::string> headers;
typedef int socket_t;

const std::string kDefaultCiphers =
    "ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES128-SHA "
    "ECDHE-ECDSA-AES256-SHA ECDHE-ECDSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA384 "
    "ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES128-SHA "
    "ECDHE-RSA-AES256-SHA ECDHE-RSA-AES128-SHA256 ECDHE-RSA-AES256-SHA384 "
    "DHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES256-GCM-SHA384 DHE-RSA-AES128-SHA "
    "DHE-RSA-AES256-SHA DHE-RSA-AES128-SHA256 DHE-RSA-AES256-SHA256 AES128-SHA";

using CancellationRequest = std::function<bool()>;
using SelectInterruptPtr = std::unique_ptr<class SelectInterrupt>;

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

class SelectInterrupt {
public:
    SelectInterrupt() {};
    ~SelectInterrupt() {};
    
    bool init(std::string& errorMsg) { return true; };
    bool notify(uint64_t value) { return true; };
    bool clear() { return true; };
    uint64_t read() { return 0; };
    int getFd() const { return -1; };
    void* getEvent() const { return nullptr; };

    // Used as special codes for pipe communication
    static const uint64_t kSendRequest;
    static const uint64_t kCloseRequest;
};

const uint64_t SelectInterrupt::kSendRequest = 1;
const uint64_t SelectInterrupt::kCloseRequest = 2;

class SelectInterruptPipe final : public SelectInterrupt {
public:
    SelectInterruptPipe() {
        _fildes[kPipeReadIndex] = -1;
        _fildes[kPipeWriteIndex] = -1;
    }

    ~SelectInterruptPipe() {
        ::close(_fildes[kPipeReadIndex]);
        ::close(_fildes[kPipeWriteIndex]);
        _fildes[kPipeReadIndex] = -1;
        _fildes[kPipeWriteIndex] = -1;
    }

    bool init(std::string& errorMsg) {
        std::lock_guard<std::mutex> lock(_fildesMutex);
        // calling init twice is a programming error
        assert(_fildes[kPipeReadIndex] == -1);
        assert(_fildes[kPipeWriteIndex] == -1);

        if (pipe(_fildes) < 0) {
            std::stringstream ss;
            ss << "SelectInterruptPipe::init() failed in pipe() call"
               << " : " << strerror(errno);
            errorMsg = ss.str();
            return false;
        }

        if (fcntl(_fildes[kPipeReadIndex], F_SETFL, O_NONBLOCK) == -1) {
            std::stringstream ss;
            ss << "SelectInterruptPipe::init() failed in fcntl(..., O_NONBLOCK) call"
               << " : " << strerror(errno);
            errorMsg = ss.str();

            _fildes[kPipeReadIndex] = -1;
            _fildes[kPipeWriteIndex] = -1;
            return false;
        }

        if (fcntl(_fildes[kPipeWriteIndex], F_SETFL, O_NONBLOCK) == -1) {
            std::stringstream ss;
            ss << "SelectInterruptPipe::init() failed in fcntl(..., O_NONBLOCK) call"
               << " : " << strerror(errno);
            errorMsg = ss.str();

            _fildes[kPipeReadIndex] = -1;
            _fildes[kPipeWriteIndex] = -1;
            return false;
        }

        return true;
    }

    bool notify(uint64_t value) {
        std::lock_guard<std::mutex> lock(_fildesMutex);

        int fd = _fildes[kPipeWriteIndex];
        if (fd == -1) return false;

        ssize_t ret = -1;
        do{
            ret = ::write(fd, &value, sizeof(value));
        } while (ret == -1 && errno == EINTR);

        // we should write 8 bytes for an uint64_t
        return ret == 8;
    }

    uint64_t read() {
        std::lock_guard<std::mutex> lock(_fildesMutex);
        int fd = _fildes[kPipeReadIndex];
        uint64_t value = 0;
        ssize_t ret = -1;
        do {
            ret = ::read(fd, &value, sizeof(value));
        } while (ret == -1 && errno == EINTR);
        return value;
    }

    bool clear() {
        return true;
    }

    int getFd() const {
        std::lock_guard<std::mutex> lock(_fildesMutex);
        return _fildes[kPipeReadIndex];
    }

private:
    // Store file descriptors used by the communication pipe. Communication
    // happens between a control thread and a background thread, which is
    // blocked on select.
    int _fildes[2];
    mutable std::mutex _fildesMutex;

    // Used to identify the read/write idx
    static const int kPipeReadIndex;
    static const int kPipeWriteIndex;
};

// File descriptor at index 0 in _fildes is the read end of the pipe
// File descriptor at index 1 in _fildes is the write end of the pipe
const int SelectInterruptPipe::kPipeReadIndex = 0;
const int SelectInterruptPipe::kPipeWriteIndex = 1;

SelectInterruptPtr create_select_interrupt() {
    return std::unique_ptr<SelectInterruptPipe>(new SelectInterruptPipe());
}

struct SocketTLSOptions {
public:
    // check validity of the object
    bool isValid() const
    {
        if (!_validated)
        {
            if (!certFile.empty() && !std::ifstream(certFile))
            {
                _errMsg = "certFile not found: " + certFile;
                return false;
            }
            if (!keyFile.empty() && !std::ifstream(keyFile))
            {
                _errMsg = "keyFile not found: " + keyFile;
                return false;
            }
            if (!caFile.empty() && caFile != kTLSCAFileDisableVerify &&
                caFile != kTLSCAFileUseSystemDefaults && !std::ifstream(caFile))
            {
                _errMsg = "caFile not found: " + caFile;
                return false;
            }

            if (certFile.empty() != keyFile.empty())
            {
                _errMsg = "certFile and keyFile must be both present, or both absent";
                return false;
            }

            _validated = true;
        }
        return true;
    };

    // the certificate presented to peers
    std::string certFile;

    // the key used for signing/encryption
    std::string keyFile;

    // the ca certificate (or certificate bundle) file containing
    // certificates to be trusted by peers; use 'SYSTEM' to
    // leverage the system defaults, use 'NONE' to disable peer verification
    std::string caFile = "SYSTEM";

    // list of ciphers (rsa, etc...)
    std::string ciphers = "DEFAULT";

    // whether tls is enabled, used for server code
    bool tls = false;

    bool hasCertAndKey() const {
        return !certFile.empty() && !keyFile.empty();
    };

    bool isUsingSystemDefaults() const {
        return caFile == kTLSCAFileUseSystemDefaults;
    };

    bool isUsingInMemoryCAs() const {
        return caFile.find(kTLSInMemoryMarker) != std::string::npos;
    };

    bool isPeerVerifyDisabled() const {
        return caFile == kTLSCAFileDisableVerify;
    };

    bool isUsingDefaultCiphers() const {
        return ciphers.empty() || ciphers == kTLSCiphersUseDefault;
    }

    const std::string& getErrorMsg() const {
        return _errMsg;
    };

    std::string getDescription() const {
        std::stringstream ss;
        ss << "TLS Options:" << std::endl;
        ss << "  certFile = " << certFile << std::endl;
        ss << "  keyFile  = " << keyFile << std::endl;
        ss << "  caFile   = " << caFile << std::endl;
        ss << "  ciphers  = " << ciphers << std::endl;
        ss << "  tls      = " << tls << std::endl;
        return ss.str();
    }

private:
    const char* kTLSCAFileUseSystemDefaults = "SYSTEM";
    const char* kTLSCAFileDisableVerify = "NONE";
    const char* kTLSCiphersUseDefault = "DEFAULT";
    const char* kTLSInMemoryMarker = "-----BEGIN CERTIFICATE-----";

    mutable std::string _errMsg;
    mutable bool _validated = false;
};

enum class PollResultType
{
    ReadyForRead = 0,
    ReadyForWrite = 1,
    Timeout = 2,
    Error = 3,
    SendRequest = 4,
    CloseRequest = 5
};

class SocketOpenSSL {
public:
    SocketOpenSSL(const SocketTLSOptions& tlsOptions, int fd = -1)
        : _sockfd(fd)
        , _ssl_connection(nullptr)
        , _ssl_context(nullptr)
        , _tlsOptions(tlsOptions) {
        std::call_once(_openSSLInitFlag, &SocketOpenSSL::openssl_initialize, this);
    }

    ~SocketOpenSSL() {
        ssl_close();
    };

    bool connect(const std::string& host, int port, std::string& err_msg) {
        bool handshakeSuccessful = false;
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

            // SNI support
            SSL_set_tlsext_host_name(_ssl_connection, host.c_str());

            // Support for server name verification
            // (The docs say that this should work from 1.0.2, and is the default from
            // 1.1.0, but it does not. To be on the safe side, the manual test
            // below is enabled for all versions prior to 1.1.0.)
            X509_VERIFY_PARAM* param = SSL_get0_param(_ssl_connection);
            X509_VERIFY_PARAM_set1_host(param, host.c_str(), host.size());
            handshakeSuccessful = openssl_client_handshake(host, err_msg);
        }

        if (!handshakeSuccessful) {
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
        std::lock_guard<std::mutex> lock(_socketMutex);
        if (_sockfd == -1) return;
        ::close(_sockfd);
        _sockfd = -1;
    }

    void socket_configure(int sockfd)
    {
        // 1. disable Nagle's algorithm
        int flag = 1;
        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char*) &flag, sizeof(flag));

        // 2. make socket non blocking
        fcntl(sockfd, F_SETFL, O_NONBLOCK);
    }

    bool is_wait_needed() {
        int err = errno;
        if (err == EWOULDBLOCK || err == EAGAIN || err == EINPROGRESS) {
            return true;
        }

        return false;
    }

    int connect_to_address(const struct addrinfo* address, std::string& err_msg) {
        err_msg = "no error";
        socket_t fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) {
            err_msg = "Cannot create a socket";
            return -1;
        }

        // set the socket to non blocking mode
        socket_configure(fd);
        int res = ::connect(fd, address->ai_addr, address->ai_addrlen);
        if (res == -1 && !is_wait_needed())
        {
            err_msg = strerror(errno);
            ::close(fd);
            return -1;
        }

        for (;;) {
            int timeoutMs = 10;
            bool readyToRead = false;
            SelectInterruptPtr selectInterrupt = create_select_interrupt();
            PollResultType pollResult = socket_poll(readyToRead, timeoutMs, fd, selectInterrupt);

            if (pollResult == PollResultType::Timeout)
            {
                continue;
            } else if (pollResult == PollResultType::Error) {
                ::close(fd);
                err_msg = std::string("Connect error: ") + strerror(errno);
                return -1;
            } else if (pollResult == PollResultType::ReadyForWrite) {
                return fd;
            } else {
                ::close(fd);
                err_msg = std::string("Connect error: ") + strerror(errno);
                return -1;
            }
        }
    }

    int poll(struct pollfd* fds, nfds_t nfds, int timeout, void** event) {
        if (event && *event) *event = nullptr;

        //
        // It was reported that on Android poll can fail and return -1 with
        // errno == EINTR, which should be a temp error and should typically
        // be handled by retrying in a loop.
        // Maybe we need to put all syscall / C functions in
        // a new IXSysCalls.cpp and wrap them all.
        //
        // The style from libuv is as such.
        //
        int ret = -1;
        do
        {
            ret = ::poll(fds, nfds, timeout);
        } while (ret == -1 && errno == EINTR);

        return ret;
    }

    PollResultType socket_poll(bool readyToRead, int timeoutMs, int sockfd, const SelectInterruptPtr& selectInterrupt) {
        PollResultType pollResult = PollResultType::ReadyForRead;

        //
        // We used to use ::select to poll but on Android 9 we get large fds out of
        // ::connect which crash in FD_SET as they are larger than FD_SETSIZE. Switching
        // to ::poll does fix that.
        //
        // However poll isn't as portable as select and has bugs on Windows, so we
        // have a shim to fallback to select on those platforms. See
        // https://github.com/mpv-player/mpv/pull/5203/files for such a select wrapper.
        //
        nfds_t nfds = 1;
        struct pollfd fds[2];
        memset(fds, 0, sizeof(fds));

        fds[0].fd = sockfd;
        fds[0].events = (readyToRead) ? POLLIN : POLLOUT;

        // this is ignored by poll, but our select based poll wrapper on Windows needs it
        fds[0].events |= POLLERR;

        // File descriptor used to interrupt select when needed
        int interruptFd = -1;
        void* interruptEvent = nullptr;
        if (selectInterrupt)
        {
            interruptFd = selectInterrupt->getFd();
            interruptEvent = selectInterrupt->getEvent();

            if (interruptFd != -1)
            {
                nfds = 2;
                fds[1].fd = interruptFd;
                fds[1].events = POLLIN;
            }
            else if (interruptEvent == nullptr)
            {
                // Emulation mode: SelectInterrupt neither supports file descriptors nor events

                // Check the selectInterrupt for requests before doing the poll().
                if (read_select_interrupt_request(selectInterrupt, &pollResult))
                {
                    return pollResult;
                }
            }
        }

        void* event = interruptEvent; // ix::poll will set event to nullptr if it wasn't signaled
        int ret = poll(fds, nfds, timeoutMs, &event);

        if (ret < 0)
        {
            pollResult = PollResultType::Error;
        }
        else if (ret == 0)
        {
            pollResult = PollResultType::Timeout;
            if (selectInterrupt && interruptFd == -1 && interruptEvent == nullptr)
            {
                // Emulation mode: SelectInterrupt neither supports fd nor events

                // Check the selectInterrupt for requests
                read_select_interrupt_request(selectInterrupt, &pollResult);
            }
        }
        else if ((interruptFd != -1 && fds[1].revents & POLLIN) || (interruptEvent != nullptr && event != nullptr))
        {
            // The InterruptEvent was signaled
            read_select_interrupt_request(selectInterrupt, &pollResult);
        }
        else if (sockfd != -1 && readyToRead && fds[0].revents & POLLIN)
        {
            pollResult = PollResultType::ReadyForRead;
        }
        else if (sockfd != -1 && !readyToRead && fds[0].revents & POLLOUT)
        {
            pollResult = PollResultType::ReadyForWrite;
            int optval = -1;
            socklen_t optlen = sizeof(optval);

            // getsockopt() puts the errno value for connect into optval so 0
            // means no-error.
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1 || optval != 0)
            {
                pollResult = PollResultType::Error;

                // set errno to optval so that external callers can have an
                // appropriate error description when calling strerror
                errno = optval;
            }
        }
        else if (sockfd != -1 && (fds[0].revents & POLLERR || fds[0].revents & POLLHUP ||
                                fds[0].revents & POLLNVAL))
        {
            pollResult = PollResultType::Error;
        }

        return pollResult;
    }


    bool read_select_interrupt_request(const SelectInterruptPtr& selectInterrupt, PollResultType* pollResult){
        uint64_t value = selectInterrupt->read();

        if (value == SelectInterrupt::kSendRequest) {
            *pollResult = PollResultType::SendRequest;
            return true;
        } else if (value == SelectInterrupt::kCloseRequest) {
            *pollResult = PollResultType::CloseRequest;
            return true;
        }

        return false;
    }

    int socket_connect(const std::string& hostname, int port, std::string& err_msg) {
        //
        // First do DNS resolution
        //
        std::string dns_err_msg;
        struct addrinfo* res = resolve_dns(hostname, port, dns_err_msg);
        if (res == nullptr) {
            return -1;
        }

        int sockfd = -1;

        // iterate through the records to find a working peer
        struct addrinfo* address;
        for (address = res; address != nullptr; address = address->ai_next) {
            //
            // Second try to connect to the remote host
            //
            sockfd = connect_to_address(address, err_msg);
            if (sockfd != -1)
            {
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
        if (server_cert == nullptr)
        {
            err_msg = "OpenSSL failed - peer didn't present a X509 certificate.";
            return false;
        }

        X509_free(server_cert);
        return true;
    };
    bool check_host(const std::string& host, const char* pattern) {
        return fnmatch(pattern, host.c_str(), 0) != FNM_NOMATCH;
    }
    bool openssl_server_handshake(std::string& err_msg) {
        while (true) {
            if (_ssl_connection == nullptr || _ssl_context == nullptr)
            {
                return false;
            }

            ERR_clear_error();
            int accept_result = SSL_accept(_ssl_connection);
            if (accept_result == 1) {
                return true;
            }
            int reason = SSL_get_error(_ssl_connection, accept_result);
            bool rc = false;
            if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) {
                rc = true;
            } else {
                err_msg = get_ssl_error(accept_result);
                rc = false;
            }

            if (!rc) {
                return false;
            }
        }
    }

    int _sockfd;
    SSL* _ssl_connection;
    SSL_CTX* _ssl_context;
    const SSL_METHOD* _ssl_method;
    SocketTLSOptions _tlsOptions;

    mutable std::mutex _mutex; // OpenSSL routines are not thread-safe
    std::mutex _socketMutex;

    SelectInterruptPtr _selectInterrupt;

    static std::once_flag _openSSLInitFlag;
    static std::atomic<bool> _openssl_initialization_successful;
};

std::once_flag SocketOpenSSL::_openSSLInitFlag;
std::atomic<bool> SocketOpenSSL::_openssl_initialization_successful(false);

class websocket_client final {
public:
    websocket_client() {
    };
    ~websocket_client() {
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
            for (int i = 0; i < max_redirections; ++i)
            {

            std::string error_msg;
            SocketTLSOptions tlsOptions;
            _tls_socket = std::unique_ptr<SocketOpenSSL>(new SocketOpenSSL(tlsOptions, -1));
    //         _perMessageDeflate = ix::make_unique<WebSocketPerMessageDeflate>();

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
    std::unique_ptr<SocketOpenSSL> _tls_socket;
};

int main() {
    websocket_client c;
    std::string url("wss://ws-feed.exchange.coinbase.com:443");
    c.set_url(url);

    std::string protocol, host;
    int port;
    c.parse_url(protocol, host, port, url);

    std::string dns_err_msg;
    struct addrinfo* address_info = resolve_dns(host, port, dns_err_msg);
    struct sockaddr_in* addr = (struct sockaddr_in *)address_info->ai_addr; 
    std::cout << "IP address: " << inet_ntoa((struct in_addr)addr->sin_addr) << std::endl;

    SocketTLSOptions tlsOptions;
    SocketOpenSSL s(tlsOptions, -1);
    std::string socket_err_msg;
    bool ssl_connect_success = s.connect(host, port, socket_err_msg);
    std::cout << "ssl connect success: " << std::boolalpha << ssl_connect_success << std::endl;
    std::cout << "socket err msg: " << socket_err_msg << std::endl;
}