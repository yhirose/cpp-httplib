# SPDX-FileCopyrightText: 2021 Andrea Pappacoda
#
# SPDX-License-Identifier: MIT

project(
  'cpp-httplib',
  'cpp',
  license: 'MIT',
  default_options: [
    'cpp_std=c++11',
    'buildtype=release',
    'b_ndebug=if-release',
    'b_lto=true',
    'warning_level=3'
  ],
  meson_version: '>=0.47.0'
)

# Check just in case downstream decides to edit the source
# and add a project version
version = meson.project_version()
python3 = find_program('python3')
if version == 'undefined'
  # Meson doesn't have regular expressions, but since it is implemented
  # in python we can be sure we can use it to parse the file manually
  version = run_command(
      python3, '-c', 'import re; raw_version = re.search("User\-Agent.*cpp\-httplib/([0-9]+\.?)+", open("httplib.h").read()).group(0); print(re.search("([0-9]+\\.?)+", raw_version).group(0))',
      check: true
  ).stdout().strip()
endif

message('cpp-httplib version ' + version)

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

cpp_httplib_dep = dependency('', required: false)

if get_option('cpp-httplib_compile')
  httplib_ch = custom_target(
    'split',
    input: 'httplib.h',
    output: ['httplib.cc', 'httplib.h'],
    command: [python3, files('split.py'), '--out', meson.current_build_dir()],
    install: true,
    install_dir: [false, get_option('includedir')]
  )
  lib = library(
    'cpp-httplib',
    sources: httplib_ch,
    dependencies: deps,
    cpp_args: args,
    version: version,
    install: true
  )
  cpp_httplib_dep = declare_dependency(compile_args: args, dependencies: deps, link_with: lib, sources: httplib_ch[1])

  import('pkgconfig').generate(
    lib,
    description: 'A C++ HTTP/HTTPS server and client library',
    extra_cflags: args,
    url: 'https://github.com/yhirose/cpp-httplib',
    version: version
  )
else
  install_headers('httplib.h')
  cpp_httplib_dep = declare_dependency(compile_args: args, dependencies: deps, include_directories: include_directories('.'))

  import('pkgconfig').generate(
    name: 'cpp-httplib',
    description: 'A C++ HTTP/HTTPS server and client library',
    install_dir: join_paths(get_option('datadir'), 'pkgconfig'),
    url: 'https://github.com/yhirose/cpp-httplib',
    version: version
  )
endif

if meson.version().version_compare('>=0.54.0')
  meson.override_dependency('cpp-httplib', cpp_httplib_dep)
endif

if get_option('cpp-httplib_test')
  subdir('test')
endif
