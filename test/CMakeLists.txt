cmake_minimum_required(VERSION 3.10)

project(Tests)

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

add_executable(adecryptify-tests-encrypt tests_encrypt.cpp)
add_executable(adecryptify-tests-decrypt tests_decrypt.cpp)

target_include_directories(adecryptify-tests-encrypt PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(adecryptify-tests-decrypt PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(adecryptify-tests-encrypt PRIVATE libaescryptify ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(adecryptify-tests-decrypt PRIVATE libaescryptify ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

# Setup the working dir for tests
set(TESTS_WORKING_DIR ${CMAKE_BINARY_DIR}/test/)
file(MAKE_DIRECTORY ${TESTS_WORKING_DIR})

# Copy required files for testing
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/my_vacation_photo.jpg
		DESTINATION ${TESTS_WORKING_DIR}/)


add_test(NAME test-encrypt COMMAND adecryptify-tests-encrypt WORKING_DIRECTORY ${TESTS_WORKING_DIR})
add_test(NAME test-decrypt COMMAND adecryptify-tests-decrypt WORKING_DIRECTORY ${TESTS_WORKING_DIR})
