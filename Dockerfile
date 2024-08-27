FROM ubuntu AS builder
WORKDIR /app
COPY httplib.h .
COPY docker/main.cc .
RUN apt update && apt install g++ -y
RUN g++ -std=c++14 -static -o server -O3 -I. -DCPPHTTPLIB_USE_POLL main.cc

FROM scratch
COPY --from=builder /app/server /server
COPY docker/index.html /html/index.html
CMD ["/server"]
