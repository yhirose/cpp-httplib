#[[
	Build options:
	* HTTPLIB_USE_OPENSSL_IF_AVAILABLE (default on)
	* HTTPLIB_USE_ZLIB_IF_AVAILABLE (default on)
	* HTTPLIB_REQUIRE_OPENSSL (default off)
	* HTTPLIB_REQUIRE_ZLIB (default off)

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

	These three variables are available after you run find_package(httplib)
	* HTTPLIB_HEADER_PATH - this is the full path to the installed header.
	* HTTPLIB_IS_USING_OPENSSL - a bool for if OpenSSL support is enabled.
	* HTTPLIB_IS_USING_ZLIB - a bool for if ZLIB support is enabled.

	Want to use precompiled headers (Cmake feature since v3.16)?
	It's as simple as doing the following (before linking):

	target_precompile_headers(httplib::httplib INTERFACE "${HTTPLIB_HEADER_PATH}")
]]
cmake_minimum_required(VERSION 3.7.0 FATAL_ERROR)
project(httplib LANGUAGES CXX)

# Change as needed to set an OpenSSL minimum version.
# This is used in the installed Cmake config file.
set(_HTTPLIB_OPENSSL_MIN_VER "1.1.1")

# Allow for a build to require OpenSSL to pass, instead of just being optional
option(HTTPLIB_REQUIRE_OPENSSL "Requires OpenSSL to be found & linked, or fails build." OFF)
option(HTTPLIB_REQUIRE_ZLIB "Requires ZLIB to be found & linked, or fails build." OFF)
# Allow for a build to casually enable OpenSSL/ZLIB support, but silenty continue if not found.
# Make these options so their automatic use can be specifically disabled (as needed)
option(HTTPLIB_USE_OPENSSL_IF_AVAILABLE "Uses OpenSSL (if available) to enable HTTPS support." ON)
option(HTTPLIB_USE_ZLIB_IF_AVAILABLE "Uses ZLIB (if available) to enable compression support." ON)

# TODO: implement the option of option to correctly split, building, and export with the split.py script.
# option(HTTPLIB_SPLIT "Uses a Python script to split the header into a header & source file." OFF)

# Threads needed for <thread> on some systems, and for <pthread.h> on Linux
find_package(Threads REQUIRED)
if(HTTPLIB_REQUIRE_OPENSSL)
	find_package(OpenSSL ${_HTTPLIB_OPENSSL_MIN_VER} REQUIRED)
elseif(HTTPLIB_USE_OPENSSL_IF_AVAILABLE)
	# Look quietly since it's optional are optional
	find_package(OpenSSL ${_HTTPLIB_OPENSSL_MIN_VER} QUIET)
endif()
if(HTTPLIB_REQUIRE_ZLIB)
	find_package(ZLIB REQUIRED)
elseif(HTTPLIB_USE_ZLIB_IF_AVAILABLE)
	find_package(ZLIB QUIET)
endif()

# Used for default, common dirs that the end-user can change (if needed)
# like CMAKE_INSTALL_INCLUDEDIR or CMAKE_INSTALL_DATADIR
include(GNUInstallDirs)

add_library(${PROJECT_NAME} INTERFACE)
# Lets you address the target with httplib::httplib
# Only useful if building in-tree, versus using it from an installation.
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

# Might be missing some, but this list is somewhat comprehensive
target_compile_features(${PROJECT_NAME} INTERFACE
	cxx_std_11
	cxx_nullptr
	cxx_noexcept
	cxx_lambdas
	cxx_override
	cxx_defaulted_functions
	cxx_attribute_deprecated
	cxx_auto_type
	cxx_decltype
	cxx_deleted_functions
	cxx_range_for
	cxx_sizeof_member
)

target_include_directories(${PROJECT_NAME} INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)


target_link_libraries(${PROJECT_NAME} INTERFACE
	# Always require threads
	Threads::Threads
	# Only link zlib & openssl if they're found
	$<$<BOOL:${ZLIB_FOUND}>:ZLIB::ZLIB>
	$<$<BOOL:${OPENSSL_FOUND}>:OpenSSL::SSL OpenSSL::Crypto>
)

# Auto-define the optional support if those packages were found
target_compile_definitions(${PROJECT_NAME} INTERFACE
	$<$<BOOL:${ZLIB_FOUND}>:CPPHTTPLIB_ZLIB_SUPPORT>
	$<$<BOOL:${OPENSSL_FOUND}>:CPPHTTPLIB_OPENSSL_SUPPORT>
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

# Creates the export httplibTargets.cmake
# This is strictly what holds compilation requirements
# and linkage information (doesn't find deps though).
install(TARGETS ${PROJECT_NAME}
	EXPORT httplibTargets
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES httplib.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES
		"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
	DESTINATION ${_TARGET_INSTALL_CMAKEDIR}
)

# NOTE: This path changes depending on if it's on Windows or Linux
install(EXPORT httplibTargets
	# Puts the targets into the httplib namespace
	# So this makes httplib::httplib linkable after doing find_package(httplib)
	NAMESPACE ${PROJECT_NAME}::
	DESTINATION ${_TARGET_INSTALL_CMAKEDIR}
)
