# This file contains C++20 module support requiring CMake 3.28+
# Included conditionally to prevent parse errors on older CMake versions

if(HTTPLIB_BUILD_MODULES)
	if(POLICY CMP0155)
		cmake_policy(SET CMP0155 NEW)
	endif()

	set(CMAKE_CXX_SCAN_FOR_MODULES ON)
	
	target_sources(${PROJECT_NAME}
		PUBLIC
			FILE_SET CXX_MODULES FILES
				"${_httplib_build_includedir}/httplib.cppm"
	)
endif()
