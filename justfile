set shell := ["bash", "-c"]

default: list

list:
    @just --list --unsorted

openssl:
    @(cd test && LSAN_OPTIONS=suppressions=lsan_suppressions.txt make)
    @(cd test && make proxy)

openssl_parallel:
    @(cd test && make test_openssl_parallel)

mbedtls:
    @(cd test && make test_mbedtls && LSAN_OPTIONS=suppressions=lsan_suppressions.txt ./test_mbedtls)
    @(cd test && make proxy_mbedtls)

mbedtls_parallel:
    @(cd test && make test_mbedtls_parallel)

wolfssl:
    @(cd test && make test_wolfssl && LSAN_OPTIONS=suppressions=lsan_suppressions.txt ./test_wolfssl)
    @(cd test && make proxy_wolfssl)

wolfssl_parallel:
    @(cd test && make test_wolfssl_parallel)

no_tls:
    @(cd test && make test_no_tls && ./test_no_tls)

no_tls_parallel:
    @(cd test && make test_no_tls_parallel)

others:
    @(cd test && make fuzz_test)
    @(cd test && make test_websocket_heartbeat && ./test_websocket_heartbeat)
    @(cd test && make test_thread_pool && ./test_thread_pool)

build:
    @(cd test && make test_split)
    @(cd test && make test_split_mbedtls)
    @(cd test && make test_split_wolfssl)

bench:
    @(cd benchmark && make bench-all)
