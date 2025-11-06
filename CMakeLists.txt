cmake_minimum_required(VERSION 3.10)
project(TCPFlowProcessor)

list(APPEND CMAKE_PREFIX_PATH "./vcpkg_installed/x64-linux")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PcapPlusPlus REQUIRED)
find_package(Arrow REQUIRED)

include_directories(include)
set(SOURCES
    src/FlowUtils.cpp
    src/Encode.cpp
    src/FlowExtractor.cpp
    src/Decode.cpp
    src/main.cpp
)

add_executable(tcp_flow_processor ${SOURCES})
target_link_libraries(tcp_flow_processor PRIVATE 
    PcapPlusPlus::Pcap++ 
    Arrow::arrow_static
)

target_include_directories(tcp_flow_processor PRIVATE
    ${ARROW_INCLUDE_DIR}
)
