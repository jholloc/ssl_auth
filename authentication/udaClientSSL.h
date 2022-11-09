#pragma once

#ifndef UDA_AUTHENTICATION_CLIENT_SSL_H
#define UDA_AUTHENTICATION_CLIENT_SSL_H

#if defined(SSLAUTHENTICATION)

// Create the SSL context and binding to the socket
// 3 UDA protocol modes: TCP without SSL/TLS, TCP and UDP both with SSL/TLS
// This set of functions is concerned only with the SSL/TLS protocol (authentication and encryption) - not with establishing socket connections or non SSL TCP transport

// Server host addressed beginng with SSL:// are assumed to be using SSL authentication. The SSL:// prefix is removed to make the connection.

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>

#include <string>

#define VERIFY_DEPTH    4
#define X509STRINGSIZE    256

struct HostData {
    std::string host_alias;
    std::string host_name;
    std::string certificate;
    std::string key;
    std::string ca_certificate;
    int port;
    bool isSSL;
};

bool getUdaClientSSLDisabled();
SSL *getUdaClientSSL();
void putUdaClientSSLSocket(int s);
void closeUdaClientSSL();
void putUdaClientSSLProtocol(int specified);
int startUdaClientSSL();
int readUdaClientSSL(void* iohandle, char* buf, int count);
int writeUdaClientSSL(void* iohandle, char* buf, int count);
void putClientHost(HostData host);

#endif // SSLAUTHENTICATION

#endif // UDA_AUTHENTICATION_CLIENT_SSL_H
