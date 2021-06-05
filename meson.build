project('httplib', 'cpp', license: 'MIT')

httplib_dep = declare_dependency(include_directories: include_directories('.'))

if meson.version().version_compare('>=0.54.0')
  meson.override_dependency('httplib', httplib_dep)
endif
