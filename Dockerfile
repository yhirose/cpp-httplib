FROM yhirose4dockerhub/ubuntu-builder:sha256:77030708e06f71ee3c283bd46c7a8a05765d4424e20ff3d7eca2cac69f54ab47 AS builder
WORKDIR /build
RUN groupadd -r user && \
    useradd -r -g user -m -d /home/user -s /bin/bash user

USER user
COPY httplib.h .
COPY docker/main.cc .
RUN g++ -std=c++23 -static -o server -O2 -I. main.cc && strip server

FROM scratch
COPY --from=builder /build/server /server
COPY docker/html/index.html /html/index.html
EXPOSE 80

ENTRYPOINT ["/server"]
CMD ["--host", "0.0.0.0", "--port", "80", "--mount", "/:./html"]
