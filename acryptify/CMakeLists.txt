cmake_minimum_required(VERSION 3.10)

# Set the project name
project(acryptify)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable
add_executable(acryptify main.cpp)

target_link_libraries(acryptify PRIVATE libaescryptify)