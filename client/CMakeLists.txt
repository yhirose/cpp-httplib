cmake_minimum_required (VERSION 3.4)

# The project
project (client)

# The version number.
set (client_VERSION_MAJOR 1)
set (client_VERSION_MINOR 0)

find_package(OpenSSL REQUIRED)

# Use static libs
set (OPENSSL_USE_STATIC_LIBS TRUE)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include ${OPENSSL_INCLUDE_DIR})

# Cpp files
set(SOURCE_FILES client.cpp)

# Libs
set(LIBRARY_FILES OpenSSL::Crypto OpenSSL::SSL)

# Compile the target
add_executable (${PROJECT_NAME} ${SOURCE_FILES})

# Link the libs
target_link_libraries(${PROJECT_NAME} ${LIBRARY_FILES})