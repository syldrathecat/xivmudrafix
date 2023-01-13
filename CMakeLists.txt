cmake_minimum_required(VERSION 2.8.12)

project(xivmudrafix LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(xivmudrafix main.cpp memory.cpp memory.hpp memory_linux.cpp format.cpp format.hpp)

install(TARGETS xivmudrafix
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
