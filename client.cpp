#include <iostream>

#include <rpc/rpc.h>
#include <netinet/tcp.h>
#include <vector>
#include "authentication/udaClientSSL.h"
#include "logging.h"

#define DB_READ_BLOCK_SIZE      32*1024 //16384
#define DB_WRITE_BLOCK_SIZE     32*1024 //16384

static int client_socket = -1;

void setHints(struct addrinfo* hints, const char* hostname)
{
    hints->ai_family = AF_UNSPEC;
    hints->ai_socktype = SOCK_STREAM;
    hints->ai_flags = 0; //AI_CANONNAME | AI_V4MAPPED | AI_ALL | AI_ADDRCONFIG ;
    hints->ai_protocol = 0;
    hints->ai_canonname = nullptr;
    hints->ai_addr = nullptr;
    hints->ai_next = nullptr;

    // RC Fix IPv6 connection for localhost
    hints->ai_family = AF_INET;
}

int createConnection(const char* hostname, int port)
{
    int window_size = DB_READ_BLOCK_SIZE;        // 128K
    int rc;

    static int max_socket_delay = 10;
    static int max_socket_attempts = 3;

    if (client_socket >= 0) {
        // Check Already Opened?
        return 0;
    }

    auto host = HostData {
        .host_alias = hostname,
        .host_name = hostname,
        .certificate = "/Users/jhollocombe/CLionProjects/ssl_auth/certificate.pem",
        .key = "/Users/jhollocombe/CLionProjects/ssl_auth/private.key",
        .ca_certificate = "/Users/jhollocombe/CLionProjects/ssl_auth/ca.cert.pem",
        .port = port,
        .isSSL = true,
    };

    putClientHost(host);
    putUdaClientSSLProtocol(1);

    // Resolve the Host and the IP protocol to be used (Hints not used)

    struct addrinfo* result = nullptr;
    struct addrinfo hints = { 0 };
    setHints(&hints, hostname);

    std::string port_str = std::to_string(port);

    errno = 0;
    if ((rc = getaddrinfo(hostname, port_str.c_str(), &hints, &result)) != 0) {
        throw std::runtime_error{ "failed to get address info" };
    }

    if (result->ai_family == AF_INET) {
        UDA_LOG(UDA_LOG_DEBUG, "Socket Connection is IPv4\n");
    } else {
        UDA_LOG(UDA_LOG_DEBUG, "Socket Connection is IPv6\n");
    }

    errno = 0;
    client_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

    if (client_socket < 0 || errno != 0) {
        throw std::runtime_error{ "failed to create socket" };
    }

    // Connect to server

    errno = 0;
    while ((rc = connect(client_socket, result->ai_addr, result->ai_addrlen)) && errno == EINTR) {}

    if (rc < 0 || (errno != 0 && errno != EINTR)) {

        // Try again for a maximum number of tries with a random time delay between attempts

        int ps;
        ps = getpid();
        srand((unsigned int)ps);                                                // Seed the random number generator with the process id
        unsigned int delay = max_socket_delay > 0 ? (unsigned int)(rand() % max_socket_delay) : 0; // random delay
        sleep(delay);
        errno = 0;                                                           // wait period
        for (int i = 0; i < max_socket_attempts; i++) {                             // try again
            while ((rc = connect(client_socket, result->ai_addr, result->ai_addrlen)) && errno == EINTR) {}

            if (rc == 0 && errno == 0) break;

            delay = max_socket_delay > 0 ? (unsigned int)(rand() % max_socket_delay) : 0;
            sleep(delay);                            // wait period
        }

        if (rc != 0 || errno != 0) {
            UDA_LOG(UDA_LOG_DEBUG, "Connect errno = %d\n", errno);
            UDA_LOG(UDA_LOG_DEBUG, "Connect rc = %d\n", rc);
            UDA_LOG(UDA_LOG_DEBUG, "Unable to connect to primary host: %s on port %d\n", hostname, port);
        }

        if (rc < 0) {
            throw std::runtime_error{ "failed to connect to server" };
        }
    }

    if (result) {
        freeaddrinfo(result);
    }

    // Set the receive and send buffer sizes

    setsockopt(client_socket, SOL_SOCKET, SO_SNDBUF, (char*)&window_size, sizeof(window_size));

    setsockopt(client_socket, SOL_SOCKET, SO_RCVBUF, (char*)&window_size, sizeof(window_size));

    // Other Socket Options

    int on = 1;
    if (setsockopt(client_socket, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on)) < 0) {
        throw std::runtime_error{ "failed to set keepalive on socket" };
    }
    on = 1;
    if (setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&on, sizeof(on)) < 0) {
        throw std::runtime_error{ "failed to set nodelay on socket" };
    }

    // Write the socket number to the SSL functions

    putUdaClientSSLSocket(client_socket);

    return 0;
}

int main()
{
    createConnection("localhost", 56565);

    if (startUdaClientSSL() != 0) {
        throw std::runtime_error{ "failed to authenticate" };
    }
    std::cout << "authentication complete" << std::endl;

    char buffer[1024];
    read(client_socket, buffer, 1024);
    std::cout << "received: " << buffer << std::endl;

    return 0;
}
