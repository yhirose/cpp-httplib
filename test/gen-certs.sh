#!/usr/bin/env bash
if [[ $(openssl version) =~ 3\.[2-9]\.[0-9]+ ]]; then
	OPENSSL_X509_FLAG='-x509v1'
else
	OPENSSL_X509_FLAG='-x509'
fi

openssl genrsa 2048 > key.pem
openssl req -new -batch -config test.conf -key key.pem | openssl x509 -days 3650 -req -signkey key.pem > cert.pem
openssl req -x509 -config test.conf -key key.pem -sha256 -days 3650 -nodes -out cert2.pem -extensions SAN
openssl genrsa 2048 > rootCA.key.pem
openssl req $OPENSSL_X509_FLAG -new -batch -config test.rootCA.conf -key rootCA.key.pem -days 1024 > rootCA.cert.pem
openssl genrsa 2048 > client.key.pem
openssl req -new -batch -config test.conf -key client.key.pem | openssl x509 -days 370 -req -CA rootCA.cert.pem -CAkey rootCA.key.pem -CAcreateserial > client.cert.pem
openssl genrsa -passout pass:test123! 2048 > key_encrypted.pem
openssl req -new -batch -config test.conf -key key_encrypted.pem | openssl x509 -days 3650 -req -signkey key_encrypted.pem > cert_encrypted.pem
openssl genrsa 2048 | openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES -passout pass:test012! -out client_encrypted.key.pem
openssl req -new -batch -config test.conf -key client_encrypted.key.pem -passin pass:test012! | openssl x509 -days 370 -req -CA rootCA.cert.pem -CAkey rootCA.key.pem -CAcreateserial > client_encrypted.cert.pem

# Certificates for IP-host hostname verification regression tests.
# cert_ip_cn.pem: CN is an IPv4 literal with NO subjectAltName. An IP host must
#                 NOT be authenticated via the CN, so verifying it against this
#                 cert must fail.
openssl req -x509 -key key.pem -sha256 -days 3650 -nodes -subj "/CN=127.0.0.1" -out cert_ip_cn.pem

# cert_ipv6.pem:  CN is an IPv6 literal plus an IPv6 iPAddress SAN for a
#                 different address. The SAN address must match; the CN address
#                 must be ignored.
openssl req -x509 -key key.pem -sha256 -days 3650 -nodes -subj "/CN=::1" -addext "subjectAltName=IP:2001:db8::1" -out cert_ipv6.pem
