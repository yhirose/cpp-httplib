# SPDX-FileCopyrightText: 2021 Andrea Pappacoda
#
# SPDX-License-Identifier: MIT

project(
  'cpp-httplib',
  'cpp',
  version: '0.9.4',
  license: 'MIT',
  default_options: [
    'buildtype=release',
    'b_ndebug=if-release',
    'b_lto=true',
    'warning_level=3'
  ],
  meson_version: '>=0.47.0'
)

deps = [dependency('threads')]
args = []

openssl_dep = dependency('openssl', version: ['>=1.1.1', '<1.1.2'], required: get_option('cpp-httplib_openssl'))
if openssl_dep.found()
  deps += openssl_dep
  args += '-DCPPHTTPLIB_OPENSSL_SUPPORT'
endif

zlib_dep = dependency('zlib', required: get_option('cpp-httplib_zlib'))
if zlib_dep.found()
  deps += zlib_dep
  args += '-DCPPHTTPLIB_ZLIB_SUPPORT'
endif

brotli_deps = [dependency('libbrotlicommon', required: get_option('cpp-httplib_brotli'))]
brotli_deps += dependency('libbrotlidec',    required: get_option('cpp-httplib_brotli'))
brotli_deps += dependency('libbrotlienc',    required: get_option('cpp-httplib_brotli'))

brotli_found_all = true
foreach brotli_dep : brotli_deps
  if not brotli_dep.found()
    brotli_found_all = false
  endif
endforeach

if brotli_found_all
  deps += brotli_deps
  args += '-DCPPHTTPLIB_BROTLI_SUPPORT'
endif

cpp_httplib_dep = dependency('', required : false)

if get_option('cpp-httplib_compile')
  python = import('python').find_installation('python3')
  httplib_ch = custom_target(
    'split',
    input: 'httplib.h',
    output: ['httplib.cc', 'httplib.h'],
    command: [python, files('split.py'), '--out', meson.current_build_dir()],
    install: true,
    install_dir: [false, get_option('includedir')]
  )
  lib = library(
    'cpp-httplib',
    sources: httplib_ch,
    dependencies: deps,
    cpp_args: args,
    install: true
  )
  cpp_httplib_dep = declare_dependency(link_with: lib, sources: httplib_ch[1])

  import('pkgconfig').generate(
    lib,
    description: 'A C++ HTTP/HTTPS server and client library',
    url: 'https://github.com/yhirose/cpp-httplib'
  )
else
  cpp_httplib_dep = declare_dependency(include_directories: include_directories('.'), dependencies: deps)
endif

if meson.version().version_compare('>=0.54.0')
  meson.override_dependency('cpp-httplib', cpp_httplib_dep)
endif
