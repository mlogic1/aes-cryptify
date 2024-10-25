cmake_minimum_required(VERSION 3.10)

# Set the project name
project(AESCryptify)

# Add subdirectories for library, encrypter and decrypter
add_subdirectory(libaescryptify)
add_subdirectory(acryptify)
add_subdirectory(adecryptify)
add_subdirectory(test)
