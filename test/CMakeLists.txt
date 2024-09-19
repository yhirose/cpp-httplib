find_package(GTest)

if(GTest_FOUND)
    if(NOT TARGET GTest::gtest_main AND TARGET GTest::Main)
        # CMake <3.20
        add_library(GTest::gtest_main INTERFACE IMPORTED)
        target_link_libraries(GTest::gtest_main INTERFACE GTest::Main)
    endif()
else()
    if(POLICY CMP0135)
        cmake_policy(SET CMP0135 NEW)
    endif()

    include(FetchContent)

    set(BUILD_GMOCK OFF)
    set(INSTALL_GTEST OFF)
    set(gtest_force_shared_crt ON)

    FetchContent_Declare(
        gtest
        URL https://github.com/google/googletest/archive/main.tar.gz
    )
    FetchContent_MakeAvailable(gtest)
endif()

find_package(CURL REQUIRED)

add_executable(httplib-test test.cc)
target_compile_options(httplib-test PRIVATE "$<$<CXX_COMPILER_ID:MSVC>:/utf-8;/bigobj>")
target_link_libraries(httplib-test PRIVATE httplib GTest::gtest_main CURL::libcurl)
gtest_discover_tests(httplib-test WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})

file(
    COPY www www2 www3 ca-bundle.crt image.jpg
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)

if(HTTPLIB_IS_USING_OPENSSL)
    execute_process(
        COMMAND ${CMAKE_CURRENT_LIST_DIR}/gen-certs.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        COMMAND_ERROR_IS_FATAL ANY
    )
endif()

add_subdirectory(fuzzing)
