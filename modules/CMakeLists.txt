add_library(httplib_module)

target_sources(httplib_module
    PUBLIC
        FILE_SET CXX_MODULES FILES
            httplib.cppm
)

target_compile_features(httplib_module PUBLIC cxx_std_20)

target_include_directories(httplib_module PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

add_library(httplib::module ALIAS httplib_module)

# Installation
install(TARGETS httplib_module
    EXPORT ${PROJECT_NAME}Targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    FILE_SET CXX_MODULES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/httplib/modules
)
