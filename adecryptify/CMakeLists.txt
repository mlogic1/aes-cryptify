cmake_minimum_required(VERSION 3.10)

# Set the project name
project(adecryptify)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable
add_executable(adecryptify main.cpp)

target_link_libraries(adecryptify PRIVATE libaescryptify)