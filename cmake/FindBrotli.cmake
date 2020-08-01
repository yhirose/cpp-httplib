# A simple FindBrotli package for Cmake's find_package function.
# Note: This find package doesn't have version support, as the version file doesn't seem to be installed on most systems.
# 
# If you want to find the static packages instead of shared (the default), define BROTLI_USE_STATIC_LIBS as TRUE.
# The targets will have the same names, but it will use the static libs.
#
# Valid find_package COMPONENTS names: "decoder", "encoder", and "common"
#
# Defines the libraries (if found): Brotli::decoder, Brotli::encoder, Brotli::common
# and the includes path variable: Brotli_INCLUDE_DIR

function(brotli_err_msg _err_msg)
	# If the package is required, throw a fatal error
	# Otherwise, if not running quietly, we throw a warning
	if(Brotli_FIND_REQUIRED)
		message(FATAL_ERROR "${_err_msg}")
	elseif(NOT Brotli_FIND_QUIETLY)
		message(WARNING "${_err_msg}")
	endif()
endfunction()

# If they asked for a specific version, warn/fail since we don't support it.
if(Brotli_FIND_VERSION)
	brotli_err_msg("FindBrotli.cmake doesn't have version support!")
endif()

# Since both decoder & encoder require the common lib (I think), force its requirement..
# if the user is requiring either of those other libs.
if(Brotli_FIND_REQUIRED_decoder OR Brotli_FIND_REQUIRED_encoder)
	set(Brotli_FIND_REQUIRED_common TRUE)
endif()

# Make PkgConfig optional, since some users (mainly Windows) don't have it.
# But it's a lot more clean than manually using find_library.
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
	if(BROTLI_USE_STATIC_LIBS)
		# Have to use _STATIC to tell PkgConfig to find the static libs.
		pkg_check_modules(Brotli_common_STATIC QUIET IMPORTED_TARGET libbrotlicommon)
		pkg_check_modules(Brotli_decoder_STATIC QUIET IMPORTED_TARGET libbrotlidec)
		pkg_check_modules(Brotli_encoder_STATIC QUIET IMPORTED_TARGET libbrotlienc)
	else()
		pkg_check_modules(Brotli_common QUIET IMPORTED_TARGET libbrotlicommon)
		pkg_check_modules(Brotli_decoder QUIET IMPORTED_TARGET libbrotlidec)
		pkg_check_modules(Brotli_encoder QUIET IMPORTED_TARGET libbrotlienc)
	endif()
endif()

# Only used if the PkgConfig libraries aren't used.
find_path(Brotli_INCLUDE_DIR
	NAMES "brotli/decode.h" "brotli/encode.h"
	PATH_SUFFIXES "include" "includes"
	DOC "The path to Brotli's include directory."
)

# Also check if Brotli_decoder was defined, as it can be passed by the end-user
if(NOT TARGET PkgConfig::Brotli_decoder AND NOT Brotli_decoder AND NOT TARGET PkgConfig::Brotli_decoder_STATIC)
	if(BROTLI_USE_STATIC_LIBS)
		list(APPEND _brotli_decoder_lib_names
			"brotlidec-static"
			"libbrotlidec-static"
		)
	else()
		list(APPEND _brotli_decoder_lib_names
			"brotlidec"
			"libbrotlidec"
		)
	endif()
	find_library(Brotli_decoder
		NAMES ${_brotli_decoder_lib_names}
		PATH_SUFFIXES
			"lib"
			"lib64"
			"libs"
			"libs64"
			"lib/x86_64-linux-gnu"
	)
endif()

# Also check if Brotli_encoder was defined, as it can be passed by the end-user
if(NOT TARGET PkgConfig::Brotli_encoder AND NOT Brotli_encoder AND NOT TARGET PkgConfig::Brotli_encoder_STATIC)
	if(BROTLI_USE_STATIC_LIBS)
		list(APPEND _brotli_encoder_lib_names
			"brotlienc-static"
			"libbrotlienc-static"
		)
	else()
		list(APPEND _brotli_encoder_lib_names
			"brotlienc"
			"libbrotlienc"
		)
	endif()
	find_library(Brotli_encoder
		NAMES ${_brotli_encoder_lib_names}
		PATH_SUFFIXES
			"lib"
			"lib64"
			"libs"
			"libs64"
			"lib/x86_64-linux-gnu"
	)
endif()

# Also check if Brotli_common was defined, as it can be passed by the end-user
if(NOT TARGET PkgConfig::Brotli_common AND NOT Brotli_common AND NOT TARGET PkgConfig::Brotli_common_STATIC)
	if(BROTLI_USE_STATIC_LIBS)
		list(APPEND _brotli_common_lib_names
			"brotlicommon-static"
			"libbrotlicommon-static"
		)
	else()
		list(APPEND _brotli_common_lib_names
			"brotlicommon"
			"libbrotlicommon"
		)
	endif()
	find_library(Brotli_common
		NAMES ${_brotli_common_lib_names}
		PATH_SUFFIXES
			"lib"
			"lib64"
			"libs"
			"libs64"
			"lib/x86_64-linux-gnu"
	)
endif()

set(_brotli_req_vars "")
# Generic loop to either create all the aliases for the end-user, or throw errors/warnings.
# Note that the case here needs to match the case we used elsewhere in this file.
foreach(_target_name "common" "decoder" "encoder")
	# The PkgConfig IMPORTED_TARGET has PkgConfig:: prefixed to it.
	if(TARGET PkgConfig::Brotli_${_target_name} OR TARGET PkgConfig::Brotli_${_target_name}_STATIC)
		set(_stat_str "")
		if(BROTLI_USE_STATIC_LIBS)
			set(_stat_str "_STATIC")
		endif()
		# Can't use generators for ALIAS targets, so you get this jank
		add_library(Brotli::${_target_name} ALIAS PkgConfig::Brotli_${_target_name}${_stat_str})

			# The PkgConfig version of the library has a slightly different path to its lib.
		if(Brotli_FIND_REQUIRED_${_target_name})
			if(BROTLI_USE_STATIC_LIBS)
				list(APPEND _brotli_req_vars "Brotli_${_target_name}_STATIC_LIBRARIES")
			else()
				list(APPEND _brotli_req_vars "Brotli_${_target_name}_LINK_LIBRARIES")
			endif()
		endif()
	# This will only trigger for libraries we found using find_library
	elseif(Brotli_${_target_name})
		add_library("Brotli::${_target_name}" UNKNOWN IMPORTED)
		# Safety-check the includes dir
		if(NOT Brotli_INCLUDE_DIR)
			brotli_err_msg("Failed to find Brotli's includes directory. Try manually defining \"Brotli_INCLUDE_DIR\" to Brotli's header path on your system.")
		endif()
		# Attach the literal library and include dir to the IMPORTED target for the end-user
		set_target_properties("Brotli::${_target_name}" PROPERTIES
			INTERFACE_INCLUDE_DIRECTORIES "${Brotli_INCLUDE_DIR}"
			IMPORTED_LOCATION "${Brotli_${_target_name}}"
		)
		# Attach the library from find_library to our required vars (if it's required)
		if(Brotli_FIND_REQUIRED_${_target_name})
			list(APPEND _brotli_req_vars "Brotli_${_target_name}")
		endif()
	# This will only happen if it's a required library but we didn't find it.
	elseif(Brotli_FIND_REQUIRED_${_target_name})
		# Only bother with an error/failure if they actually required the lib.
		brotli_err_msg("Failed to find Brotli's ${_target_name} library. Try manually defining \"Brotli_${_target_name}\" to its path on your system.")
		# If the compnent was required but not found, you set XXX_FOUND to false to signify failure to find component(s)
		# This is used in find_package_handle_standard_args's HANDLE_COMPONENTS (I think)
		set(Brotli_FOUND FALSE)
	endif()
endforeach()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Brotli
	FOUND_VAR Brotli_FOUND
	REQUIRED_VARS ${_brotli_req_vars}
	HANDLE_COMPONENTS
)

if(Brotli_FOUND)
	include(FindPackageMessage)
	foreach(_lib_name ${_brotli_req_vars})
		# TODO: remove this if/when The Cmake PkgConfig file fixes the non-quiet message about libbrotlicommon being found.
		if(${_lib_name} MATCHES "common")
			# This avoids a duplicate "Found Brotli: /usr/lib/libbrotlicommon.so" type message.
			continue()
		endif()
		# Double-expand the var to get the actual path instead of the variable's name.
		find_package_message(Brotli "Found Brotli: ${${_lib_name}}"
			"[${${_lib_name}}][${Brotli_INCLUDE_DIR}]"
		)
	endforeach()
endif()
