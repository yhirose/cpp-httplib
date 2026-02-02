set shell := ["bash", "-c"]

default: list

list:
    @just --list --unsorted

openssl:
    @(cd test && make test && ./test)
    @(cd test && make proxy)

mbedtls:
    @(cd test && make test_mbedtls && ./test_mbedtls)
    @(cd test && make proxy_mbedtls)

fuzz:
    @(cd test && make fuzz_test)

build:
    @(cd test && make test_split)
    @(cd test && make test_split_mbedtls)
