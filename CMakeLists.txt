cmake_minimum_required(VERSION 2.6)

project(dumppcap2udp C)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/src/cmake)
find_package(PCAP REQUIRED)

set(CMAKE_INSTALL_PREFIX /usr)

add_definitions(-Os -Wall -Werror -std=gnu99 -g3)

add_subdirectory(src)
