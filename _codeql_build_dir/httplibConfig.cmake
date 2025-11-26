# Generates a macro to auto-configure everything

####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was httplibConfig.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

# Setting these here so they're accessible after install.
# Might be useful for some users to check which settings were used.
set(HTTPLIB_IS_USING_OPENSSL TRUE)
set(HTTPLIB_IS_USING_ZLIB TRUE)
set(HTTPLIB_IS_COMPILED OFF)
set(HTTPLIB_IS_USING_BROTLI FALSE)
set(HTTPLIB_IS_USING_NON_BLOCKING_GETADDRINFO ON)
set(HTTPLIB_VERSION 0.27.0)

include(CMakeFindDependencyMacro)

# We add find_dependency calls here to not make the end-user have to call them.
find_dependency(Threads)
if(TRUE)
	# OpenSSL COMPONENTS were added in Cmake v3.11
	if(CMAKE_VERSION VERSION_LESS "3.11")
		find_dependency(OpenSSL 3.0.0)
	else()
		# Once the COMPONENTS were added, they were made optional when not specified.
		# Since we use both, we need to search for both.
		find_dependency(OpenSSL 3.0.0 COMPONENTS Crypto SSL)
	endif()
	set(httplib_OpenSSL_FOUND ${OpenSSL_FOUND})
endif()
if(TRUE)
	find_dependency(ZLIB)
	set(httplib_ZLIB_FOUND ${ZLIB_FOUND})
endif()

if(FALSE)
	# Needed so we can use our own FindBrotli.cmake in this file.
	# Note that the FindBrotli.cmake file is installed in the same dir as this file.
	list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
	set(BROTLI_USE_STATIC_LIBS )
	find_dependency(Brotli COMPONENTS common encoder decoder)
	set(httplib_Brotli_FOUND ${Brotli_FOUND})
endif()

if(1)
	set(httplib_fd_zstd_quiet_arg)
	if(${CMAKE_FIND_PACKAGE_NAME}_FIND_QUIETLY)
		set(httplib_fd_zstd_quiet_arg QUIET)
	endif()
	set(httplib_fd_zstd_required_arg)
	if(${CMAKE_FIND_PACKAGE_NAME}_FIND_REQUIRED)
		set(httplib_fd_zstd_required_arg REQUIRED)
	endif()
	find_package(zstd QUIET)
	if(NOT zstd_FOUND)
		find_package(PkgConfig ${httplib_fd_zstd_quiet_arg} ${httplib_fd_zstd_required_arg})
		if(PKG_CONFIG_FOUND)
			pkg_check_modules(zstd ${httplib_fd_zstd_quiet_arg} ${httplib_fd_zstd_required_arg} IMPORTED_TARGET libzstd)

			if(TARGET PkgConfig::zstd)
				add_library(zstd::libzstd ALIAS PkgConfig::zstd)
			endif()
		endif()
	endif()
	set(httplib_zstd_FOUND ${zstd_FOUND})
endif()

# Mildly useful for end-users
# Not really recommended to be used though
set_and_check(HTTPLIB_INCLUDE_DIR "${PACKAGE_PREFIX_DIR}/include")
# Lets the end-user find the header path with the header appended
# This is helpful if you're using Cmake's pre-compiled header feature
set_and_check(HTTPLIB_HEADER_PATH "${PACKAGE_PREFIX_DIR}/include/httplib.h")

check_required_components(httplib)

# Brings in the target library, but only if all required components are found
if(NOT DEFINED httplib_FOUND OR httplib_FOUND)
	include("${CMAKE_CURRENT_LIST_DIR}/httplibTargets.cmake")
endif()

# Outputs a "found httplib /usr/include/httplib.h" message when using find_package(httplib)
include(FindPackageMessage)
if(TARGET httplib::httplib)
	set(HTTPLIB_FOUND TRUE)

	# Since the compiled version has a lib, show that in the message
	if(OFF)
		# The list of configurations is most likely just 1 unless they installed a debug & release
		get_target_property(_httplib_configs httplib::httplib "IMPORTED_CONFIGURATIONS")
		# Need to loop since the "IMPORTED_LOCATION" property isn't want we want.
		# Instead, we need to find the IMPORTED_LOCATION_RELEASE or IMPORTED_LOCATION_DEBUG which has the lib path.
		foreach(_httplib_conf "${_httplib_configs}")
			# Grab the path to the lib and sets it to HTTPLIB_LIBRARY
			get_target_property(HTTPLIB_LIBRARY httplib::httplib "IMPORTED_LOCATION_${_httplib_conf}")
			# Check if we found it
			if(HTTPLIB_LIBRARY)
				break()
			endif()
		endforeach()

		unset(_httplib_configs)
		unset(_httplib_conf)

		find_package_message(httplib "Found httplib: ${HTTPLIB_LIBRARY} (found version \"${HTTPLIB_VERSION}\")" "[${HTTPLIB_LIBRARY}][${HTTPLIB_HEADER_PATH}]")
	else()
		find_package_message(httplib "Found httplib: ${HTTPLIB_HEADER_PATH} (found version \"${HTTPLIB_VERSION}\")" "[${HTTPLIB_HEADER_PATH}]")
	endif()
endif()
