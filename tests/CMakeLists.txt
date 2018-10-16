cmake_minimum_required (VERSION 3.4)

# The project
project (tests)

# The version number.
set (test_VERSION_MAJOR 1)
set (test_VERSION_MINOR 0)

enable_testing()
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Use static libs
set (OPENSSL_USE_STATIC_LIBS TRUE)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include ${GTEST_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

# Cpp files
set(SOURCE_FILES tests.cpp)

# Libs
set(LIBRARY_FILES ${CMAKE_THREAD_LIBS_INIT} gtest_main gtest OpenSSL::Crypto OpenSSL::SSL)

# Compile the target
add_executable (${PROJECT_NAME} ${SOURCE_FILES})

# Link the libs
target_link_libraries(${PROJECT_NAME} ${LIBRARY_FILES})

add_test(AllTestsInTests ${PROJECT_NAME})