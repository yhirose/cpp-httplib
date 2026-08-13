FROM alpine:3.24

ARG auth="basic"
ARG port="3128"

RUN groupadd -r user && \
    useradd -r -g user -m -d /home/user -s /bin/bash user

USER user

RUN apk update && apk add --no-cache squid

COPY ./${auth}_squid.conf /etc/squid/squid.conf
COPY ./${auth}_passwd /etc/squid/passwd

EXPOSE ${port}

CMD ["/usr/sbin/squid", "-N"]
