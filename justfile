set shell := ["bash", "-c"]

default: list

list:
    @just --list --unsorted

openssl:
    @(cd test && make test && LSAN_OPTIONS=suppressions=lsan_suppressions.txt ./test)
    @(cd test && make proxy)

openssl_parallel:
    @(cd test && make test_openssl_parallel)

mbedtls:
    @(cd test && make test_mbedtls && LSAN_OPTIONS=suppressions=lsan_suppressions.txt ./test_mbedtls)
    @(cd test && make proxy_mbedtls)

mbedtls_parallel:
    @(cd test && make test_mbedtls_parallel)

no_tls:
    @(cd test && make test_no_tls && ./test_no_tls)

no_tls_parallel:
    @(cd test && make test_no_tls_parallel)

fuzz:
    @(cd test && make fuzz_test)

build:
    @(cd test && make test_split)
    @(cd test && make test_split_mbedtls)
