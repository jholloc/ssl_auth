cmake_minimum_required(VERSION 3.10)
project(ssl_auth)

set(CMAKE_CXX_STANDARD 17)

find_package( OpenSSL REQUIRED )

add_definitions(-DSSLAUTHENTICATION)

add_subdirectory(authentication)

include_directories(/usr/include/tirpc)

add_executable(ssl_auth_server server.cpp)
target_link_libraries(ssl_auth_server PRIVATE authentication-server-objects)

add_executable(ssl_auth_client client.cpp)
target_link_libraries(ssl_auth_client PRIVATE authentication-client-objects)
