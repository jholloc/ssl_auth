#include <iostream>
#include <netinet/tcp.h>
#include <netdb.h>
#include <cstring>

#include "authentication/udaServerSSL.h"
#include "logging.h"

#define DB_READ_BLOCK_SIZE      32*1024 //16384

static int server_socket = -1;

void createConnection()
{
    errno = 0;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0 || errno != 0) {
        throw std::runtime_error{ "failed to create socket" };
    }

    // Connect to server

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(56565);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        throw std::runtime_error{ "failed to bind" };
    }

    if (listen(server_fd, 3) < 0) {
        throw std::runtime_error{ "failed to listen" };
    }

    std::cout << "waiting for connections" << std::endl;

    socklen_t addr_len = sizeof(addr);
    if ((server_socket = accept(server_fd, (sockaddr*)&addr, &addr_len)) < 0) {
        throw std::runtime_error{ "failed to accept connection" };
    }

    putUdaServerSSLSocket(server_socket);
}

int main()
{
    createConnection();

    Config config = {};
    config.cert = "";
    config.key = "";
    config.ca = "";
    config.crlist = "";

    if (startUdaServerSSL(config) != 0) {
        throw std::runtime_error{ "failed to authenticate" };
    }
    std::cout << "authentication complete" << std::endl;

    const char* msg = "Hello from server";
    send(server_socket, msg, strlen(msg), 0);

    std::cout << "Hello message sent" << std::endl;

    return 0;
}

