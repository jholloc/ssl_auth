find_package( OpenSSL REQUIRED )

add_library( authentication-client-objects udaClientSSL.cpp )
add_library( authentication-server-objects udaServerSSL.cpp )

target_link_libraries( authentication-client-objects PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries( authentication-server-objects PUBLIC OpenSSL::SSL OpenSSL::Crypto)