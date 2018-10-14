cmake_minimum_required (VERSION 3.4)

# The project
project (httplibtest)

# The version number.
set (test_VERSION_MAJOR 1)
set (test_VERSION_MINOR 0)

find_package(OpenSSL REQUIRED)
enable_testing()
find_package(GTest REQUIRED)

# Use static libs
set (OPENSSL_USE_STATIC_LIBS TRUE)

include_directories(${GTEST_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

# Cpp files
set(SOURCE_FILES httplibtest.cpp)

# Libs
set(LIBRARY_FILES OpenSSL::Crypto OpenSSL::SSL ${GTEST_BOTH_LIBRARIES})

# Compile the target
add_executable (${PROJECT_NAME} ${SOURCE_FILES})

# Link the libs
target_link_libraries(${PROJECT_NAME} ${LIBRARY_FILES})

add_test(AllTestsInTest ${PROJECT_NAME})