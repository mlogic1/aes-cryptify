cmake_minimum_required(VERSION 3.10)

# Set the project name
project(libaescryptify)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Add the executable
add_library(libaescryptify STATIC src/codec.cpp)

set(LIBAESCRYPTIFY_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_include_directories(libaescryptify PUBLIC ${LIBAESCRYPTIFY_INCLUDE_DIR})
target_include_directories(libaescryptify PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(libaescryptify PRIVATE ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
