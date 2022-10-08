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

SelectInterruptPtr createSelectInterrupt() {
    return std::unique_ptr<SelectInterruptPipe>(new SelectInterruptPipe());
}

class DNSLookup : public std::enable_shared_from_this<DNSLookup> {
public:
    DNSLookup(const std::string& hostname, int port, int64_t wait = DNSLookup::kDefaultWait)
        : _hostname(hostname)
        , _port(port)
        , _wait(wait)
        , _res(nullptr)
        , _done(false)
    {
        ;
    };
    ~DNSLookup() = default;

    struct addrinfo* resolve(std::string& errMsg,
                                    const CancellationRequest& isCancellationRequested,
                                    bool cancellable = true)
    {
        return cancellable ? resolveCancellable(errMsg, isCancellationRequested)
                            : resolveUnCancellable(errMsg, isCancellationRequested);
    };

    void release(struct addrinfo* addr)
    {
        freeaddrinfo(addr);
    };

private:
    struct addrinfo* resolveCancellable(
        std::string& errMsg, const CancellationRequest& isCancellationRequested)
    {
        errMsg = "no error";

        // Can only be called once, otherwise we would have to manage a pool
        // of background thread which is overkill for our usage.
        if (_done)
        {
            return nullptr; // programming error, create a second DNSLookup instance
                            // if you need a second lookup.
        }

        //
        // Good resource on thread forced termination
        // https://www.bo-yang.net/2017/11/19/cpp-kill-detached-thread
        //
        auto ptr = shared_from_this();
        std::weak_ptr<DNSLookup> self(ptr);

        int port = _port;
        std::string hostname(_hostname);

        // We make the background thread doing the work a shared pointer
        // instead of a member variable, because it can keep running when
        // this object goes out of scope, in case of cancellation
        auto t = std::make_shared<std::thread>(&DNSLookup::run, this, self, hostname, port);
        t->detach();

        while (!_done)
        {
            // Wait for 1 milliseconds, to see if the bg thread has terminated.
            // We do not use a condition variable to wait, as destroying this one
            // if the bg thread is alive can cause undefined behavior.
            std::this_thread::sleep_for(std::chrono::milliseconds(_wait));

            // Were we cancelled ?
            if (isCancellationRequested())
            {
                errMsg = "cancellation requested";
                return nullptr;
            }
        }

        // Maybe a cancellation request got in before the bg terminated ?
        if (isCancellationRequested())
        {
            errMsg = "cancellation requested";
            return nullptr;
        }

        errMsg = getErrMsg();
        return getRes();
    }

    struct addrinfo* resolveUnCancellable(
        std::string& errMsg, const CancellationRequest& isCancellationRequested)
    {
        errMsg = "no error";

        // Maybe a cancellation request got in before the background thread terminated ?
        if (isCancellationRequested())
        {
            errMsg = "cancellation requested";
            return nullptr;
        }

        return getAddrInfo(_hostname, _port, errMsg);
    };

    static struct addrinfo* getAddrInfo(const std::string& hostname,
                                        int port,
                                        std::string& errMsg) {
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        std::string sport = std::to_string(port);

        struct addrinfo* res;
        int getaddrinfo_result = getaddrinfo(hostname.c_str(), sport.c_str(), &hints, &res);
        if (getaddrinfo_result)
        {
            errMsg = gai_strerror(getaddrinfo_result);
            res = nullptr;
        }
        return res;
    };

    void run(std::weak_ptr<DNSLookup> self,
                        std::string hostname,
                        int port) // thread runner
    {
        // We don't want to read or write into members variables of an object that could be
        // gone, so we use temporary variables (res) or we pass in by copy everything that
        // getAddrInfo needs to work.
        std::string errMsg;
        struct addrinfo* res = getAddrInfo(hostname, port, errMsg);

        if (auto lock = self.lock())
        {
            // Copy result into the member variables
            setRes(res);
            setErrMsg(errMsg);

            _done = true;
        }
    };

    void setErrMsg(const std::string& errMsg)
    {
        std::lock_guard<std::mutex> lock(_errMsgMutex);
        _errMsg = errMsg;
    };
    const std::string& getErrMsg()
    {
        std::lock_guard<std::mutex> lock(_errMsgMutex);
        return _errMsg;
    };

    void setRes(struct addrinfo* addr)
    {
        std::lock_guard<std::mutex> lock(_resMutex);
        _res = addr;
    };
    struct addrinfo* getRes()
    {
        std::lock_guard<std::mutex> lock(_resMutex);
        return _res;
    };

    std::string _hostname;
    int _port;
    int64_t _wait;
    const static int64_t kDefaultWait;

    struct addrinfo* _res;
    std::mutex _resMutex;

    std::string _errMsg;
    std::mutex _errMsgMutex;

    std::atomic<bool> _done;
};

const int64_t DNSLookup::kDefaultWait = 1; // ms


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
        std::call_once(_openSSLInitFlag, &SocketOpenSSL::openSSLInitialize, this);
    }

    ~SocketOpenSSL() {
        ssl_close();
    };

    bool accept(std::string& errMsg) {
        bool handshakeSuccessful = false;
        {
            std::lock_guard<std::mutex> lock(_mutex);

            if (!_openSSLInitializationSuccessful) {
                errMsg = "OPENSSL_init_ssl failure";
                return false;
            }

            if (_sockfd == -1) {
                return false;
            }

            {
                const SSL_METHOD* method = SSLv23_server_method();
                if (method == nullptr)
                {
                    errMsg = "SSLv23_server_method failure";
                    _ssl_context = nullptr;
                } else {
                    _ssl_method = method;
                    _ssl_context = SSL_CTX_new(_ssl_method);
                    if (_ssl_context) {
                        SSL_CTX_set_mode(_ssl_context, SSL_MODE_ENABLE_PARTIAL_WRITE);
                        SSL_CTX_set_mode(_ssl_context, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
                        SSL_CTX_set_options(_ssl_context,
                                            SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
                    }
                }
            }

            if (_ssl_context == nullptr) {
                return false;
            }

            ERR_clear_error();
            if (_tlsOptions.hasCertAndKey()) {
                if (SSL_CTX_use_certificate_chain_file(_ssl_context, _tlsOptions.certFile.c_str()) != 1) {
                    auto sslErr = ERR_get_error();
                    errMsg = "OpenSSL failed - SSL_CTX_use_certificate_chain_file(\"" +
                                _tlsOptions.certFile + "\") failed: ";
                    errMsg += ERR_error_string(sslErr, nullptr);
                } else if (SSL_CTX_use_PrivateKey_file(_ssl_context, _tlsOptions.keyFile.c_str(), SSL_FILETYPE_PEM) != 1) {
                    auto sslErr = ERR_get_error();
                    errMsg = "OpenSSL failed - SSL_CTX_use_PrivateKey_file(\"" +
                                _tlsOptions.keyFile + "\") failed: ";
                    errMsg += ERR_error_string(sslErr, nullptr);
                }
            }


            ERR_clear_error();
            if (!_tlsOptions.isPeerVerifyDisabled()) {
                if (_tlsOptions.isUsingSystemDefaults()) {
                    if (SSL_CTX_set_default_verify_paths(_ssl_context) == 0) {
                        auto sslErr = ERR_get_error();
                        errMsg = "OpenSSL failed - SSL_CTX_default_verify_paths loading failed: ";
                        errMsg += ERR_error_string(sslErr, nullptr);
                    }
                } else {
                    if (_tlsOptions.isUsingInMemoryCAs()) {
                        // Load from memory
                        openSSLAddCARootsFromString(_tlsOptions.caFile);
                    } else {
                        const char* root_ca_file = _tlsOptions.caFile.c_str();
                        STACK_OF(X509_NAME) * rootCAs;
                        rootCAs = SSL_load_client_CA_file(root_ca_file);
                        if (rootCAs == NULL) {
                            auto sslErr = ERR_get_error();
                            errMsg = "OpenSSL failed - SSL_load_client_CA_file('" +
                                        _tlsOptions.caFile + "') failed: ";
                            errMsg += ERR_error_string(sslErr, nullptr);
                        } else {
                            SSL_CTX_set_client_CA_list(_ssl_context, rootCAs);
                            if (SSL_CTX_load_verify_locations(_ssl_context, root_ca_file, nullptr) != 1) {
                                auto sslErr = ERR_get_error();
                                errMsg = "OpenSSL failed - SSL_CTX_load_verify_locations(\"" +
                                            _tlsOptions.caFile + "\") failed: ";
                                errMsg += ERR_error_string(sslErr, nullptr);
                            }
                        }
                    }
                }

                SSL_CTX_set_verify(_ssl_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
                SSL_CTX_set_verify_depth(_ssl_context, 4);
            } else {
                SSL_CTX_set_verify(_ssl_context, SSL_VERIFY_NONE, nullptr);
            }
            if (_tlsOptions.isUsingDefaultCiphers()) {
                if (SSL_CTX_set_cipher_list(_ssl_context, kDefaultCiphers.c_str()) != 1) {
                    return false;
                }
            } else if (SSL_CTX_set_cipher_list(_ssl_context, _tlsOptions.ciphers.c_str()) != 1) {
                return false;
            }

            _ssl_connection = SSL_new(_ssl_context);
            if (_ssl_connection == nullptr) {
                errMsg = "OpenSSL failed to connect";
                SSL_CTX_free(_ssl_context);
                _ssl_context = nullptr;
                return false;
            }

            SSL_set_ecdh_auto(_ssl_connection, 1);
            SSL_set_fd(_ssl_connection, _sockfd);
            handshakeSuccessful = openSSLServerHandshake(errMsg);
        }

        if (!handshakeSuccessful) {
            ssl_close();
            return false;
        }

        return true;
    }

    bool connect(const std::string& host, int port, std::string& errMsg, const CancellationRequest& isCancellationRequested) {
        bool handshakeSuccessful = false;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            if (!_openSSLInitializationSuccessful) {
                errMsg = "OPENSSL_init_ssl failure";
                return false;
            }

            _sockfd = socket_connect(host, port, errMsg, isCancellationRequested);
            if (_sockfd == -1) return false;
            _ssl_context = openSSLCreateContext(errMsg);
            if (_ssl_context == nullptr) {
                return false;
            }

            if (!handleTLSOptions(errMsg)) {
                return false;
            }

            _ssl_connection = SSL_new(_ssl_context);
            if (_ssl_connection == nullptr) {
                errMsg = "OpenSSL failed to connect";
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
            handshakeSuccessful = openSSLClientHandshake(host, errMsg, isCancellationRequested);
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
    ssize_t ecv(void* buf, size_t nbyte) {
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

    int connect_to_address(const struct addrinfo* address, std::string& errMsg, const CancellationRequest& isCancellationRequested) {
        errMsg = "no error";
        socket_t fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) {
            errMsg = "Cannot create a socket";
            return -1;
        }

        // set the socket to non blocking mode
        socket_configure(fd);
        int res = ::connect(fd, address->ai_addr, address->ai_addrlen);
        if (res == -1 && !is_wait_needed())
        {
            errMsg = strerror(errno);
            ::close(fd);
            return -1;
        }

        for (;;) {
            if (isCancellationRequested && isCancellationRequested()) {
                ::close(fd);
                errMsg = "Cancelled";
                return -1;
            }

            int timeoutMs = 10;
            bool readyToRead = false;
            SelectInterruptPtr selectInterrupt = createSelectInterrupt();
            PollResultType pollResult = socket_poll(readyToRead, timeoutMs, fd, selectInterrupt);

            if (pollResult == PollResultType::Timeout)
            {
                continue;
            } else if (pollResult == PollResultType::Error) {
                ::close(fd);
                errMsg = std::string("Connect error: ") + strerror(errno);
                return -1;
            } else if (pollResult == PollResultType::ReadyForWrite) {
                return fd;
            } else {
                ::close(fd);
                errMsg = std::string("Connect error: ") + strerror(errno);
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
                if (readSelectInterruptRequest(selectInterrupt, &pollResult))
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
                readSelectInterruptRequest(selectInterrupt, &pollResult);
            }
        }
        else if ((interruptFd != -1 && fds[1].revents & POLLIN) || (interruptEvent != nullptr && event != nullptr))
        {
            // The InterruptEvent was signaled
            readSelectInterruptRequest(selectInterrupt, &pollResult);
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


    bool readSelectInterruptRequest(const SelectInterruptPtr& selectInterrupt, PollResultType* pollResult){
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

    int socket_connect(const std::string& hostname, int port, std::string& errMsg, const CancellationRequest& isCancellationRequested) {
        //
        // First do DNS resolution
        //
        auto dnsLookup = std::make_shared<DNSLookup>(hostname, port);
        struct addrinfo* res = dnsLookup->resolve(errMsg, isCancellationRequested);
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
            sockfd = connect_to_address(address, errMsg, isCancellationRequested);
            if (sockfd != -1)
            {
                break;
            }
        }

        freeaddrinfo(res);
        return sockfd;
    }

    void openSSLInitialize() {
        if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr)) return;

        (void) OpenSSL_add_ssl_algorithms();
        (void) SSL_load_error_strings();
    };
    std::string getSSLError(int ret) {
        unsigned long e;
        int err = SSL_get_error(_ssl_connection, ret);
        if (err == SSL_ERROR_WANT_CONNECT || err == SSL_ERROR_WANT_ACCEPT) {
            return "OpenSSL failed - connection failure";
        } else if (err == SSL_ERROR_WANT_X509_LOOKUP) {
            return "OpenSSL failed - x509 error";
        } else if (err == SSL_ERROR_SYSCALL) {
            e = ERR_get_error();
            if (e > 0) {
                std::string errMsg("OpenSSL failed - ");
                errMsg += ERR_error_string(e, nullptr);
                return errMsg;
            } else if (e == 0 && ret == 0) {
                return "OpenSSL failed - received early EOF";
            } else {
                return "OpenSSL failed - underlying BIO reported an I/O error";
            }
        } else if (err == SSL_ERROR_SSL) {
            e = ERR_get_error();
            std::string errMsg("OpenSSL failed - ");
            errMsg += ERR_error_string(e, nullptr);
            return errMsg;
        } else if (err == SSL_ERROR_NONE) {
            return "OpenSSL failed - err none";
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            return "OpenSSL failed - err zero return";
        } else {
            return "OpenSSL failed - unknown error";
        }
    };
    SSL_CTX* openSSLCreateContext(std::string& errMsg) {
        const SSL_METHOD* method = SSLv23_client_method();
        if (method == nullptr) {
            errMsg = "SSLv23_client_method failure";
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

    bool openSSLAddCARootsFromString(const std::string roots) {
        // Create certificate store
        X509_STORE* certificate_store = SSL_CTX_get_cert_store(_ssl_context);
        if (certificate_store == nullptr) return false;

        // Configure to allow intermediate certs
        X509_STORE_set_flags(certificate_store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);

        // Create a new buffer and populate it with the roots
        BIO* buffer = BIO_new_mem_buf((void*) roots.c_str(), static_cast<int>(roots.length()));
        if (buffer == nullptr) return false;

        // Read each root in the buffer and add to the certificate store
        bool success = true;
        size_t number_of_roots = 0;

        while (true) {
            // Read the next root in the buffer
            X509* root = PEM_read_bio_X509_AUX(buffer, nullptr, nullptr, (void*) "");
            if (root == nullptr) {
                // No more certs left in the buffer, we're done.
                ERR_clear_error();
                break;
            }

            // Try adding the root to the certificate store
            ERR_clear_error();
            if (!X509_STORE_add_cert(certificate_store, root)) {
                // Failed to add. If the error is unrelated to the x509 lib or the cert already
                // exists, we're safe to continue.
                unsigned long error = ERR_get_error();
                if (ERR_GET_LIB(error) != ERR_LIB_X509 || ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                    // Failed. Clean up and bail.
                    success = false;
                    X509_free(root);
                    break;
                }
            }

            // Clean up and loop
            X509_free(root);
            number_of_roots++;
        }

        // Clean up buffer
        BIO_free(buffer);

        // Make sure we loaded at least one certificate.
        if (number_of_roots == 0) success = false;

        return success;
    };
    bool openSSLClientHandshake(const std::string& hostname, std::string& errMsg, const CancellationRequest& cancellation_requested) {
        while (true) {
            if (_ssl_connection == nullptr || _ssl_context == nullptr) {
                return false;
            }

            if (cancellation_requested()) {
                errMsg = "cancellation requested";
                return false;
            }

            ERR_clear_error();
            int connect_result = SSL_connect(_ssl_connection);
            if (connect_result == 1) {
                return openSSLCheckServerCert(_ssl_connection, hostname, errMsg);
            }
            int reason = SSL_get_error(_ssl_connection, connect_result);
            bool rc = false;
            if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) {
                rc = true;
            } else {
                errMsg = getSSLError(connect_result);
                rc = false;
            }

            if (!rc) {
                return false;
            }
        }
    };
    bool openSSLCheckServerCert(SSL* ssl, const std::string& hostname, std::string& errMsg) {
        X509* server_cert = SSL_get_peer_certificate(ssl);
        if (server_cert == nullptr)
        {
            errMsg = "OpenSSL failed - peer didn't present a X509 certificate.";
            return false;
        }

        X509_free(server_cert);
        return true;
    };
    bool checkHost(const std::string& host, const char* pattern) {
        return fnmatch(pattern, host.c_str(), 0) != FNM_NOMATCH;
    }
    bool handleTLSOptions(std::string& errMsg) {
        ERR_clear_error();
        if (_tlsOptions.hasCertAndKey()) {
            if (SSL_CTX_use_certificate_chain_file(_ssl_context, _tlsOptions.certFile.c_str()) != 1) {
                auto sslErr = ERR_get_error();
                errMsg = "OpenSSL failed - SSL_CTX_use_certificate_chain_file(\"" +
                            _tlsOptions.certFile + "\") failed: ";
                errMsg += ERR_error_string(sslErr, nullptr);
            } else if (SSL_CTX_use_PrivateKey_file(_ssl_context, _tlsOptions.keyFile.c_str(), SSL_FILETYPE_PEM) != 1) {
                auto sslErr = ERR_get_error();
                errMsg = "OpenSSL failed - SSL_CTX_use_PrivateKey_file(\"" + _tlsOptions.keyFile +
                            "\") failed: ";
                errMsg += ERR_error_string(sslErr, nullptr);
            } else if (!SSL_CTX_check_private_key(_ssl_context)) {
                auto sslErr = ERR_get_error();
                errMsg = "OpenSSL failed - cert/key mismatch(\"" + _tlsOptions.certFile + ", " +
                            _tlsOptions.keyFile + "\")";
                errMsg += ERR_error_string(sslErr, nullptr);
            }
        }

        ERR_clear_error();
        if (!_tlsOptions.isPeerVerifyDisabled()) {
            if (_tlsOptions.isUsingSystemDefaults()) {
                if (SSL_CTX_set_default_verify_paths(_ssl_context) == 0) {
                    auto sslErr = ERR_get_error();
                    errMsg = "OpenSSL failed - SSL_CTX_default_verify_paths loading failed: ";
                    errMsg += ERR_error_string(sslErr, nullptr);
                    return false;
                }
            } else {
                if (_tlsOptions.isUsingInMemoryCAs()) {
                    // Load from memory
                    openSSLAddCARootsFromString(_tlsOptions.caFile);
                } else {
                    if (SSL_CTX_load_verify_locations(_ssl_context, _tlsOptions.caFile.c_str(), NULL) != 1) {
                        auto sslErr = ERR_get_error();
                        errMsg = "OpenSSL failed - SSL_CTX_load_verify_locations(\"" +
                                    _tlsOptions.caFile + "\") failed: ";
                        errMsg += ERR_error_string(sslErr, nullptr);
                        return false;
                    }
                }
            }

            SSL_CTX_set_verify(_ssl_context, SSL_VERIFY_PEER, [](int preverify, X509_STORE_CTX*) -> int { return preverify; });
            SSL_CTX_set_verify_depth(_ssl_context, 4);
        } else {
            SSL_CTX_set_verify(_ssl_context, SSL_VERIFY_NONE, nullptr);
        }

        if (_tlsOptions.isUsingDefaultCiphers()) {
            if (SSL_CTX_set_cipher_list(_ssl_context, kDefaultCiphers.c_str()) != 1) {
                auto sslErr = ERR_get_error();
                errMsg = "OpenSSL failed - SSL_CTX_set_cipher_list(\"" + kDefaultCiphers +
                            "\") failed: ";
                errMsg += ERR_error_string(sslErr, nullptr);
                return false;
            }
        } else if (SSL_CTX_set_cipher_list(_ssl_context, _tlsOptions.ciphers.c_str()) != 1) {
            auto sslErr = ERR_get_error();
            errMsg = "OpenSSL failed - SSL_CTX_set_cipher_list(\"" + _tlsOptions.ciphers +
                        "\") failed: ";
            errMsg += ERR_error_string(sslErr, nullptr);
            return false;
        }

        return true;
    };
    bool openSSLServerHandshake(std::string& errMsg) {
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
                errMsg = getSSLError(accept_result);
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
    static std::atomic<bool> _openSSLInitializationSuccessful;
};

std::once_flag SocketOpenSSL::_openSSLInitFlag;
std::atomic<bool> SocketOpenSSL::_openSSLInitializationSuccessful(false);

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
            m_socket = std::unique_ptr<SocketOpenSSL>(new SocketOpenSSL(tlsOptions, -1));
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
    std::unique_ptr<SocketOpenSSL> m_socket;
};

int main() {
    websocket_client c;
    std::string url("wss://ws-feed.exchange.coinbase.com:443");
    c.set_url(url);

    std::string protocol, host;
    int port;
    c.parse_url(protocol, host, port, url);

    DNSLookup dns_lookup(host, port);
    std::string err_msg;
    CancellationRequest cancellation_request;
    addrinfo* address_info = dns_lookup.resolve(err_msg, cancellation_request);
    std::cout << "address_info: " << address_info << std::endl;
}