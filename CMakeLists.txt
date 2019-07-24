cmake_minimum_required(VERSION 3.7.0)
project(httplib)

set(CMAKE_CXX_STANDARD 11)

# Include
include(GNUInstallDirs)
include(ExternalProject)

add_library(${PROJECT_NAME} INTERFACE)
target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_11)

target_include_directories(${PROJECT_NAME} INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>)

install(TARGETS ${PROJECT_NAME} EXPORT httplibConfig
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES httplib.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

install(EXPORT httplibConfig DESTINATION share/httplib/cmake)

export(TARGETS ${PROJECT_NAME} FILE httplibConfig.cmake)

#add_subdirectory(example)
#add_subdirectory(test)