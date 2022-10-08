#include <string>
#include <functional>
#include <unordered_map>
#include <stdexcept>
#include <iostream>

typedef std::unordered_map<std::string, std::string> headers;

class websocket_client {
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

    void connect(const std::string& url, const headers& h, int timeoutSecs){
            std::string protocol, host;
            int port;
            std::string url_copy(url);
            parse_url(protocol, host, port, url_copy);
    //     
    //     const int maxRedirections = 10;
    //     for (int i = 0; i < maxRedirections; ++i)
    //     {
    //         // Parse the URL
    //         if (!UrlParser::parse(remoteUrl, protocol, host, path, query, port))
    //         {
    //             std::stringstream ss;
    //             ss << "Could not parse url: '" << url << "'";
    //             throw std::excpetion(ss.str());
    //         }

    //         std::string errorMsg;
    //         bool tls = protocol == "wss";
    //         _socket = createSocket(tls, -1, errorMsg, _socketTLSOptions);
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
    //     }

    //     return result;
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
};

int main() {
    websocket_client c;
    std::string url("wss://ws-feed.exchange.coinbase.com:443");
    c.set_url(url);

    std::string protocol, host;
    int port;
    c.parse_url(protocol, host, port, url);
}