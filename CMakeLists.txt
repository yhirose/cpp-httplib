cmake_minimum_required (VERSION 3.4)

# The project
project(cpp-httplib)

# The version number.
set(pod_VERSION_MAJOR 1)
set(pod_VERSION_MINOR 0)

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "./../../bin")

# Call sub CMakeLists.txt !
add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(httplibtest)