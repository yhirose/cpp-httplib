cmake_minimum_required (VERSION 2.6)

# The project
project(DECENTNET)

# The version number.
set(pod_VERSION_MAJOR 1)
set(pod_VERSION_MINOR 0)

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "./../../bin")

# Call sub CMakeLists.txt !
add_subdirectory(pod)
add_subdirectory(central-authority)