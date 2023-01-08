cmake_minimum_required (VERSION 3.8)
     
project (encryptions)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_STANDARD 20)

include_directories(./src)

add_executable(feistel src/demo/feistel.cxx)
add_executable(rsa src/demo/rsa.cxx)