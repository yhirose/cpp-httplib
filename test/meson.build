# SPDX-FileCopyrightText: 2021 Andrea Pappacoda
#
# SPDX-License-Identifier: MIT

gtest_dep = dependency('gtest', main: true)
libcurl_dep = dependency('libcurl')
openssl = find_program('openssl')
test_conf = files('test.conf')
req_x509_flag = openssl.version().version_compare('>=3.2.0') ? '-x509v1' : '-x509'

key_pem = custom_target(
  'key_pem',
  output: 'key.pem',
  command: [openssl, 'genrsa', '-out', '@OUTPUT@', '2048']
)

temp_req = custom_target(
  'temp_req',
  input: key_pem,
  output: 'temp_req',
  command: [openssl, 'req', '-new', '-batch', '-config', test_conf, '-key', '@INPUT@', '-out', '@OUTPUT@']
)

cert_pem = custom_target(
  'cert_pem',
  input: [temp_req, key_pem],
  output: 'cert.pem',
  command: [openssl, 'x509', '-in', '@INPUT0@', '-days', '3650', '-req', '-signkey', '@INPUT1@', '-out', '@OUTPUT@']
)

cert2_pem = custom_target(
  'cert2_pem',
  input: key_pem,
  output: 'cert2.pem',
  command: [openssl, 'req', req_x509_flag, '-config', test_conf, '-key', '@INPUT@', '-sha256', '-days', '3650', '-nodes', '-out', '@OUTPUT@', '-extensions', 'SAN']
)

key_encrypted_pem = custom_target(
  'key_encrypted_pem',
  output: 'key_encrypted.pem',
  command: [openssl, 'genrsa', '-passout', 'pass:test123!', '-out', '@OUTPUT@', '2048']
)

cert_encrypted_pem = custom_target(
  'cert_encrypted_pem',
  input: key_encrypted_pem,
  output: 'cert_encrypted.pem',
  command: [openssl, 'req', req_x509_flag, '-config', test_conf, '-key', '@INPUT@', '-sha256', '-days', '3650', '-nodes', '-out', '@OUTPUT@', '-extensions', 'SAN']
)

rootca_key_pem = custom_target(
  'rootca_key_pem',
  output: 'rootCA.key.pem',
  command: [openssl, 'genrsa', '-out', '@OUTPUT@', '2048']
)

rootca_cert_pem = custom_target(
  'rootca_cert_pem',
  input: rootca_key_pem,
  output: 'rootCA.cert.pem',
  command: [openssl, 'req', req_x509_flag, '-new', '-batch', '-config', files('test.rootCA.conf'), '-key', '@INPUT@', '-days', '1024', '-out', '@OUTPUT@']
)

client_key_pem = custom_target(
  'client_key_pem',
  output: 'client.key.pem',
  command: [openssl, 'genrsa', '-out', '@OUTPUT@', '2048']
)

client_temp_req = custom_target(
  'client_temp_req',
  input: client_key_pem,
  output: 'client_temp_req',
  command: [openssl, 'req', '-new', '-batch', '-config', test_conf, '-key', '@INPUT@', '-out', '@OUTPUT@']
)

client_cert_pem = custom_target(
  'client_cert_pem',
  input: [client_temp_req, rootca_cert_pem, rootca_key_pem],
  output: 'client.cert.pem',
  command: [openssl, 'x509', '-in', '@INPUT0@', '-days', '370', '-req', '-CA', '@INPUT1@', '-CAkey', '@INPUT2@', '-CAcreateserial', '-out', '@OUTPUT@']
)

# Encrypted client key: make an unencrypted key + cert first, then wrap the same
# key two ways. Mbed TLS 4.x dropped DES/PBES1, while Ubuntu's Mbed TLS 2.28 has
# no PBES2-AES, so ship both and let test.cc pick by version.
client_encrypted_tmp_key_pem = custom_target(
  'client_encrypted_tmp_key_pem',
  output: 'client_encrypted.tmp.key.pem',
  command: [openssl, 'genrsa', '-out', '@OUTPUT@', '2048']
)

client_encrypted_temp_req = custom_target(
  'client_encrypted_temp_req',
  input: client_encrypted_tmp_key_pem,
  output: 'client_encrypted_temp_req',
  command: [openssl, 'req', '-new', '-batch', '-config', test_conf, '-key', '@INPUT@', '-out', '@OUTPUT@']
)

client_encrypted_cert_pem = custom_target(
  'client_encrypted_cert_pem',
  input: [client_encrypted_temp_req, rootca_cert_pem, rootca_key_pem],
  output: 'client_encrypted.cert.pem',
  command: [openssl, 'x509', '-in', '@INPUT0@', '-days', '370', '-req', '-CA', '@INPUT1@', '-CAkey', '@INPUT2@', '-CAcreateserial', '-out', '@OUTPUT@']
)

client_encrypted_key_pem = custom_target(
  'client_encrypted_key_pem',
  input: client_encrypted_tmp_key_pem,
  output: 'client_encrypted.key.pem',
  command: [openssl, 'pkcs8', '-topk8', '-v2', 'aes-256-cbc', '-in', '@INPUT@', '-passout', 'pass:test012!', '-out', '@OUTPUT@']
)

client_encrypted_pbes1_key_pem = custom_target(
  'client_encrypted_pbes1_key_pem',
  input: client_encrypted_tmp_key_pem,
  output: 'client_encrypted_pbes1.key.pem',
  command: [openssl, 'pkcs8', '-topk8', '-v1', 'PBE-SHA1-3DES', '-in', '@INPUT@', '-passout', 'pass:test012!', '-out', '@OUTPUT@']
)

# Certificates for IP-host hostname verification regression tests.
# cert_ip_cn.pem: CN is an IPv4 literal with NO subjectAltName, so verifying an
# IP host against it must fail (an IP is never matched via the CN).
cert_ip_cn_pem = custom_target(
  'cert_ip_cn_pem',
  input: key_pem,
  output: 'cert_ip_cn.pem',
  command: [openssl, 'req', '-x509', '-key', '@INPUT@', '-sha256', '-days', '3650', '-nodes', '-subj', '/CN=127.0.0.1', '-out', '@OUTPUT@']
)

# cert_ipv6.pem: CN is an IPv6 literal plus a different IPv6 iPAddress SAN; the
# SAN address must match and the CN address must be ignored.
cert_ipv6_pem = custom_target(
  'cert_ipv6_pem',
  input: key_pem,
  output: 'cert_ipv6.pem',
  command: [openssl, 'req', '-x509', '-key', '@INPUT@', '-sha256', '-days', '3650', '-nodes', '-subj', '/CN=::1', '-addext', 'subjectAltName=IP:2001:db8::1', '-out', '@OUTPUT@']
)

# Copy test files to the build directory
configure_file(input: 'ca-bundle.crt', output: 'ca-bundle.crt', copy: true)
configure_file(input: 'image.jpg',     output: 'image.jpg',     copy: true)
subdir('www')
subdir('www2'/'dir')
subdir('www3'/'dir')

# New GoogleTest versions require new C++ standards
test_options = []
if gtest_dep.version().version_compare('>=1.17.0')
  test_options += 'cpp_std=c++17'
elif gtest_dep.version().version_compare('>=1.13.0')
  test_options += 'cpp_std=c++14'
endif

test(
  'main',
  executable(
    'main',
    'test.cc',
    dependencies: [
      cpp_httplib_dep,
      gtest_dep,
      libcurl_dep
    ],
    override_options: test_options
  ),
  depends: [
    key_pem,
    cert_pem,
    cert2_pem,
    key_encrypted_pem,
    cert_encrypted_pem,
    rootca_key_pem,
    rootca_cert_pem,
    client_key_pem,
    client_cert_pem,
    client_encrypted_key_pem,
    client_encrypted_pbes1_key_pem,
    client_encrypted_cert_pem,
    cert_ip_cn_pem,
    cert_ipv6_pem
  ],
  workdir: meson.current_build_dir(),
  timeout: 300
)
