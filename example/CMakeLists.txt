set(HTTPLIB_EXAMPLES
    benchmark
    client
    hello
    redirect
    server
    simplecli
    simplesvr
    ssecli
    ssesvr
    upload
)

foreach(example IN LISTS HTTPLIB_EXAMPLES)
    add_executable(httplib-${example} ${example}.cc)
    target_link_libraries(httplib-${example} PRIVATE httplib)
endforeach()

if(HTTPLIB_IS_USING_OPENSSL)
    file(
        COPY ca-bundle.crt
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
    )
    find_program(OPENSSL_COMMAND
        NAMES openssl
        PATHS ${OPENSSL_INCLUDE_DIR}/../bin
        REQUIRED
    )
    execute_process(
        COMMAND ${OPENSSL_COMMAND} genrsa 2048
        OUTPUT_FILE key.pem
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND_ERROR_IS_FATAL ANY
    )
    execute_process(
        COMMAND ${OPENSSL_COMMAND} req -new -batch -key key.pem
        COMMAND ${OPENSSL_COMMAND} x509 -days 3650 -req -signkey key.pem
        OUTPUT_FILE cert.pem
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND_ERROR_IS_FATAL ANY
    )
endif()
