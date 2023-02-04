cmake_minimum_required (VERSION 3.8)
     
project (encryptions)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_STANDARD 20)

include_directories(./src)

add_executable(feistel src/feistel.cxx)
add_executable(rsa src/rsa.cxx)
add_executable(aes src/aes.cxx)
add_executable(modes src/modes.cxx)
add_executable(hash src/hash.cxx)
add_executable(diffie_hellman src/diffie_hellman.cxx)