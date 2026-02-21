# A lightweight find module for Mbed TLS that works with older CMake versions.
#
# Result variables:
#   MbedTLS_FOUND
#   MbedTLS_INCLUDE_DIRS
#   MbedTLS_LIBRARIES
#
# Imported targets:
#   MbedTLS::mbedtls
#   MbedTLS::mbedx509
#   MbedTLS::mbedcrypto

find_path(MbedTLS_INCLUDE_DIR
  NAMES mbedtls/version.h
)

find_library(MbedTLS_mbedcrypto_LIBRARY
  NAMES mbedcrypto
)

find_library(MbedTLS_mbedx509_LIBRARY
  NAMES mbedx509
)

find_library(MbedTLS_mbedtls_LIBRARY
  NAMES mbedtls
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(MbedTLS
  REQUIRED_VARS
    MbedTLS_INCLUDE_DIR
    MbedTLS_mbedcrypto_LIBRARY
    MbedTLS_mbedx509_LIBRARY
    MbedTLS_mbedtls_LIBRARY
)

if(MbedTLS_FOUND)
  set(MbedTLS_INCLUDE_DIRS "${MbedTLS_INCLUDE_DIR}")
  set(MbedTLS_LIBRARIES
    "${MbedTLS_mbedtls_LIBRARY}"
    "${MbedTLS_mbedx509_LIBRARY}"
    "${MbedTLS_mbedcrypto_LIBRARY}"
  )

  if(NOT TARGET MbedTLS::mbedcrypto)
    add_library(MbedTLS::mbedcrypto UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbedcrypto PROPERTIES
      IMPORTED_LOCATION "${MbedTLS_mbedcrypto_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
    )
  endif()

  if(NOT TARGET MbedTLS::mbedx509)
    add_library(MbedTLS::mbedx509 UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbedx509 PROPERTIES
      IMPORTED_LOCATION "${MbedTLS_mbedx509_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
      INTERFACE_LINK_LIBRARIES MbedTLS::mbedcrypto
    )
  endif()

  if(NOT TARGET MbedTLS::mbedtls)
    add_library(MbedTLS::mbedtls UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbedtls PROPERTIES
      IMPORTED_LOCATION "${MbedTLS_mbedtls_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
      INTERFACE_LINK_LIBRARIES MbedTLS::mbedx509
    )
  endif()
endif()

mark_as_advanced(
  MbedTLS_INCLUDE_DIR
  MbedTLS_mbedcrypto_LIBRARY
  MbedTLS_mbedx509_LIBRARY
  MbedTLS_mbedtls_LIBRARY
)
