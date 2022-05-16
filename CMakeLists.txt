#[[
	Build options:
	* BUILD_SHARED_LIBS (default off) builds as a shared library (if HTTPLIB_COMPILE is ON)
	* HTTPLIB_USE_OPENSSL_IF_AVAILABLE (default on)
	* HTTPLIB_USE_ZLIB_IF_AVAILABLE (default on)
	* HTTPLIB_REQUIRE_OPENSSL (default off)
	* HTTPLIB_REQUIRE_ZLIB (default off)
	* HTTPLIB_USE_BROTLI_IF_AVAILABLE (default on)
	* HTTPLIB_REQUIRE_BROTLI (default off)
	* HTTPLIB_COMPILE (default off)
	* BROTLI_USE_STATIC_LIBS - tells Cmake to use the static Brotli libs (only works if you have them installed).
	* OPENSSL_USE_STATIC_LIBS - tells Cmake to use the static OpenSSL libs (only works if you have them installed).

	-------------------------------------------------------------------------------

	After installation with Cmake, a find_package(httplib) is available.
	This creates a httplib::httplib target (if found).
	It can be linked like so:

	target_link_libraries(your_exe httplib::httplib)

	The following will build & install for later use.

	Linux/macOS:

	mkdir -p build
	cd build
	cmake -DCMAKE_BUILD_TYPE=Release ..
	sudo cmake --build . --target install

	Windows:

	mkdir build
	cd build
	cmake ..
	runas /user:Administrator "cmake --build . --config Release --target install"

	-------------------------------------------------------------------------------

	These variables are available after you run find_package(httplib)
	* HTTPLIB_HEADER_PATH - this is the full path to the installed header (e.g. /usr/include/httplib.h).
	* HTTPLIB_IS_USING_OPENSSL - a bool for if OpenSSL support is enabled.
	* HTTPLIB_IS_USING_ZLIB - a bool for if ZLIB support is enabled.
	* HTTPLIB_IS_USING_BROTLI - a bool for if Brotli support is enabled.
	* HTTPLIB_IS_COMPILED - a bool for if the library is compiled, or otherwise header-only.
	* HTTPLIB_INCLUDE_DIR - the root path to httplib's header (e.g. /usr/include).
	* HTTPLIB_LIBRARY - the full path to the library if compiled (e.g. /usr/lib/libhttplib.so).
	* httplib_VERSION or HTTPLIB_VERSION - the project's version string.
	* HTTPLIB_FOUND - a bool for if the target was found.

	Want to use precompiled headers (Cmake feature since v3.16)?
	It's as simple as doing the following (before linking):

	target_precompile_headers(httplib::httplib INTERFACE "${HTTPLIB_HEADER_PATH}")

	-------------------------------------------------------------------------------

	FindPython3 requires Cmake v3.12
	ARCH_INDEPENDENT option of write_basic_package_version_file() requires Cmake v3.14
]]
cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)

# Get the CPPHTTPLIB_VERSION value and use it as a version
# This gets the string with the CPPHTTPLIB_VERSION value from the header.
# This is so the maintainer doesn't actually need to update this manually.
file(STRINGS httplib.h _raw_version_string REGEX "CPPHTTPLIB_VERSION \"([0-9]+\\.[0-9]+\\.[0-9]+)\"")

# Needed since git tags have "v" prefixing them.
# Also used if the fallback to user agent string is being used.
string(REGEX MATCH "([0-9]+\\.?)+" _httplib_version "${_raw_version_string}")

project(httplib VERSION ${_httplib_version} LANGUAGES CXX)

# Change as needed to set an OpenSSL minimum version.
# This is used in the installed Cmake config file.
set(_HTTPLIB_OPENSSL_MIN_VER "1.1.1")

# Allow for a build to require OpenSSL to pass, instead of just being optional
option(HTTPLIB_REQUIRE_OPENSSL "Requires OpenSSL to be found & linked, or fails build." OFF)
option(HTTPLIB_REQUIRE_ZLIB "Requires ZLIB to be found & linked, or fails build." OFF)
# Allow for a build to casually enable OpenSSL/ZLIB support, but silenty continue if not found.
# Make these options so their automatic use can be specifically disabled (as needed)
option(HTTPLIB_USE_OPENSSL_IF_AVAILABLE "Uses OpenSSL (if available) to enable HTTPS support." ON)
option(HTTPLIB_USE_ZLIB_IF_AVAILABLE "Uses ZLIB (if available) to enable Zlib compression support." ON)
# Lets you compile the program as a regular library instead of header-only
option(HTTPLIB_COMPILE "If ON, uses a Python script to split the header into a compilable header & source file (requires Python v3)." OFF)
# Just setting this variable here for people building in-tree
if(HTTPLIB_COMPILE)
	set(HTTPLIB_IS_COMPILED TRUE)
endif()

option(HTTPLIB_REQUIRE_BROTLI "Requires Brotli to be found & linked, or fails build." OFF)
option(HTTPLIB_USE_BROTLI_IF_AVAILABLE "Uses Brotli (if available) to enable Brotli decompression support." ON)
# Defaults to static library
option(BUILD_SHARED_LIBS "Build the library as a shared library instead of static. Has no effect if using header-only." OFF)
if (BUILD_SHARED_LIBS AND WIN32 AND HTTPLIB_COMPILE)
	# Necessary for Windows if building shared libs
	# See https://stackoverflow.com/a/40743080
	set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# Threads needed for <thread> on some systems, and for <pthread.h> on Linux
set(THREADS_PREFER_PTHREAD_FLAG true)
find_package(Threads REQUIRED)
# Since Cmake v3.11, Crypto & SSL became optional when not specified as COMPONENTS.
if(HTTPLIB_REQUIRE_OPENSSL)
	find_package(OpenSSL ${_HTTPLIB_OPENSSL_MIN_VER} COMPONENTS Crypto SSL REQUIRED)
elseif(HTTPLIB_USE_OPENSSL_IF_AVAILABLE)
	find_package(OpenSSL ${_HTTPLIB_OPENSSL_MIN_VER} COMPONENTS Crypto SSL QUIET)
endif()
# Just setting this variable here for people building in-tree
if(OPENSSL_FOUND)
	set(HTTPLIB_IS_USING_OPENSSL TRUE)
endif()

if(HTTPLIB_REQUIRE_ZLIB)
	find_package(ZLIB REQUIRED)
elseif(HTTPLIB_USE_ZLIB_IF_AVAILABLE)
	find_package(ZLIB QUIET)
endif()
# Just setting this variable here for people building in-tree
# FindZLIB doesn't have a ZLIB_FOUND variable, so check the target.
if(TARGET ZLIB::ZLIB)
	set(HTTPLIB_IS_USING_ZLIB TRUE)
endif()

# Adds our cmake folder to the search path for find_package
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
if(HTTPLIB_REQUIRE_BROTLI)
	find_package(Brotli COMPONENTS encoder decoder common REQUIRED)
elseif(HTTPLIB_USE_BROTLI_IF_AVAILABLE)
	find_package(Brotli COMPONENTS encoder decoder common QUIET)
endif()
# Just setting this variable here for people building in-tree
if(Brotli_FOUND)
	set(HTTPLIB_IS_USING_BROTLI TRUE)
endif()

# Used for default, common dirs that the end-user can change (if needed)
# like CMAKE_INSTALL_INCLUDEDIR or CMAKE_INSTALL_DATADIR
include(GNUInstallDirs)

if(HTTPLIB_COMPILE)
	# Put the split script into the build dir
	configure_file(split.py "${CMAKE_CURRENT_BINARY_DIR}/split.py"
		COPYONLY
	)
	# Needs to be in the same dir as the python script
	configure_file(httplib.h "${CMAKE_CURRENT_BINARY_DIR}/httplib.h"
		COPYONLY
	)

	# Used outside of this if-else
	set(_INTERFACE_OR_PUBLIC PUBLIC)
	# Brings in the Python3_EXECUTABLE path we can use.
	find_package(Python3 REQUIRED)
	# Actually split the file
	# Keeps the output in the build dir to not pollute the main dir
	execute_process(COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_BINARY_DIR}/split.py"
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		ERROR_VARIABLE _httplib_split_error
	)
	if(_httplib_split_error)
		message(FATAL_ERROR "Failed when trying to split cpp-httplib with the Python script.\n${_httplib_split_error}")
	endif()

	# split.py puts output in "out"
	set(_httplib_build_includedir "${CMAKE_CURRENT_BINARY_DIR}/out")
	# This will automatically be either static or shared based on the value of BUILD_SHARED_LIBS
	add_library(${PROJECT_NAME} "${_httplib_build_includedir}/httplib.cc")
	target_sources(${PROJECT_NAME}
		PUBLIC
			$<BUILD_INTERFACE:${_httplib_build_includedir}/httplib.h>
			$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/httplib.h>
	)
	set_target_properties(${PROJECT_NAME}
		PROPERTIES
			VERSION ${${PROJECT_NAME}_VERSION}
			SOVERSION ${${PROJECT_NAME}_VERSION_MAJOR}
	)
else()
	# This is for header-only.
	set(_INTERFACE_OR_PUBLIC INTERFACE)
	add_library(${PROJECT_NAME} INTERFACE)
	set(_httplib_build_includedir "${CMAKE_CURRENT_SOURCE_DIR}")
endif()
# Lets you address the target with httplib::httplib
# Only useful if building in-tree, versus using it from an installation.
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

# Require C++11
target_compile_features(${PROJECT_NAME} ${_INTERFACE_OR_PUBLIC}
	cxx_std_11
)

target_include_directories(${PROJECT_NAME} ${_INTERFACE_OR_PUBLIC}
    $<BUILD_INTERFACE:${_httplib_build_includedir}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Always require threads
target_link_libraries(${PROJECT_NAME} ${_INTERFACE_OR_PUBLIC}
		Threads::Threads
		# Needed for Windows libs on Mingw, as the pragma comment(lib, "xyz") aren't triggered.
		$<$<PLATFORM_ID:Windows>:ws2_32>
		$<$<PLATFORM_ID:Windows>:crypt32>
		$<$<PLATFORM_ID:Windows>:cryptui>
		# Can't put multiple targets in a single generator expression or it bugs out.
		$<$<BOOL:${HTTPLIB_IS_USING_BROTLI}>:Brotli::common>
		$<$<BOOL:${HTTPLIB_IS_USING_BROTLI}>:Brotli::encoder>
		$<$<BOOL:${HTTPLIB_IS_USING_BROTLI}>:Brotli::decoder>
		$<$<BOOL:${HTTPLIB_IS_USING_ZLIB}>:ZLIB::ZLIB>
		$<$<BOOL:${HTTPLIB_IS_USING_OPENSSL}>:OpenSSL::SSL>
		$<$<BOOL:${HTTPLIB_IS_USING_OPENSSL}>:OpenSSL::Crypto>
)

# Set the definitions to enable optional features
target_compile_definitions(${PROJECT_NAME} ${_INTERFACE_OR_PUBLIC}
	$<$<BOOL:${HTTPLIB_IS_USING_BROTLI}>:CPPHTTPLIB_BROTLI_SUPPORT>
	$<$<BOOL:${HTTPLIB_IS_USING_ZLIB}>:CPPHTTPLIB_ZLIB_SUPPORT>
	$<$<BOOL:${HTTPLIB_IS_USING_OPENSSL}>:CPPHTTPLIB_OPENSSL_SUPPORT>
)

# Cmake's find_package search path is different based on the system
# See https://cmake.org/cmake/help/latest/command/find_package.html for the list
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	set(_TARGET_INSTALL_CMAKEDIR "${CMAKE_INSTALL_PREFIX}/cmake/${PROJECT_NAME}")
else()
	# On Non-Windows, it should be /usr/lib/cmake/<name>/<name>Config.cmake
	# NOTE: This may or may not work for macOS...
	set(_TARGET_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
endif()

include(CMakePackageConfigHelpers)

# Configures the meta-file httplibConfig.cmake.in to replace variables with paths/values/etc.
configure_package_config_file("${PROJECT_NAME}Config.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
	INSTALL_DESTINATION "${_TARGET_INSTALL_CMAKEDIR}"
	# Passes the includedir install path
	PATH_VARS CMAKE_INSTALL_FULL_INCLUDEDIR
	# There aren't any components, so don't use the macro
	NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

if(HTTPLIB_COMPILE)
	write_basic_package_version_file("${PROJECT_NAME}ConfigVersion.cmake"
		# Example: if you find_package(httplib 0.5.4)
		# then anything >= 0.5 and <= 1.0 is accepted
		COMPATIBILITY SameMajorVersion
	)
else()
	write_basic_package_version_file("${PROJECT_NAME}ConfigVersion.cmake"
		# Example: if you find_package(httplib 0.5.4)
		# then anything >= 0.5 and <= 1.0 is accepted
		COMPATIBILITY SameMajorVersion
		# Tells Cmake that it's a header-only lib
		# Mildly useful for end-users :)
		ARCH_INDEPENDENT
	)
endif()

# Creates the export httplibTargets.cmake
# This is strictly what holds compilation requirements
# and linkage information (doesn't find deps though).
install(TARGETS ${PROJECT_NAME}
	EXPORT httplibTargets
)

install(FILES "${_httplib_build_includedir}/httplib.h" TYPE INCLUDE)

install(FILES
		"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
		"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
		# Install it so it can be used later by the httplibConfig.cmake file.
		# Put it in the same dir as our config file instead of a global path so we don't potentially stomp on other packages.
		"${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindBrotli.cmake"
	DESTINATION ${_TARGET_INSTALL_CMAKEDIR}
)

# NOTE: This path changes depending on if it's on Windows or Linux
install(EXPORT httplibTargets
	# Puts the targets into the httplib namespace
	# So this makes httplib::httplib linkable after doing find_package(httplib)
	NAMESPACE ${PROJECT_NAME}::
	DESTINATION ${_TARGET_INSTALL_CMAKEDIR}
)
