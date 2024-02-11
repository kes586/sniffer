cmake_minimum_required(VERSION 3.0.0)
project(pcap VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)

enable_testing()
set(CMAKE_CXX_STANDARD 11)
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
add_executable(pcap main.cpp pcap_interface.h pcap_interface.cpp)
target_link_libraries(pcap -lpcap)

include(CPack)


