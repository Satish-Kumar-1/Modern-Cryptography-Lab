cmake_minimum_required(VERSION 3.16)
project(SecureFileEncryption LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(crypto main.cpp)
target_link_libraries(crypto PRIVATE OpenSSL::Crypto)

if(MSVC)
    target_compile_options(crypto PRIVATE /W4 /permissive-)
else()
    target_compile_options(crypto PRIVATE -Wall -Wextra -Wpedantic)
endif()
