FROM ubuntu AS builder
WORKDIR /build
COPY httplib.h .
COPY docker/main.cc .
RUN apt update && apt install g++ -y
RUN g++ -std=c++23 -static -o server -O2 -I. -DCPPHTTPLIB_USE_POLL main.cc && strip server

FROM scratch
COPY --from=builder /build/server /server
COPY docker/html/index.html /html/index.html
EXPOSE 80
CMD ["/server"]
