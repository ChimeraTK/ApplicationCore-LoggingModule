PROJECT(ChimeraTK-ApplicationCore-LoggingModule)
cmake_minimum_required(VERSION 3.16)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules)

set(${PROJECT_NAME}_MAJOR_VERSION 01)
set(${PROJECT_NAME}_MINOR_VERSION 01)
set(${PROJECT_NAME}_PATCH_VERSION 00)
include(cmake/set_version_numbers.cmake)

# Find the ControlSystemAdapter
find_package(ChimeraTK-ApplicationCore 03.00 REQUIRED)

FIND_PACKAGE(Boost COMPONENTS date_time REQUIRED)

include(cmake/set_default_build_to_release.cmake)
include(cmake/set_default_flags.cmake)

# linker flags
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--export-dynamic ${ChimeraTK-ControlSystemAdapter_LINK_FLAGS}")

include_directories(${CMAKE_SOURCE_DIR}/include)
file(GLOB headers "${CMAKE_SOURCE_DIR}/include/*.h")
set(${PROJECT_NAME}_INCLUDE_DIRS ${${PROJECT_NAME}_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/include/ ${CMAKE_SOURCE_DIR}/Modules/include/)
aux_source_directory(${CMAKE_SOURCE_DIR}/src library_sources)

# Create the executables for automated unit testing.
option(BUILD_TESTS "Build test programs" ON)
if(BUILD_TESTS)
  enable_testing()
  add_subdirectory("${PROJECT_SOURCE_DIR}/tests")
endif()

# C++ library
add_library(${PROJECT_NAME} SHARED ${library_sources} ${headers} ${module_headers})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${${PROJECT_NAME}_FULL_LIBRARY_VERSION}
                                                 SOVERSION ${${PROJECT_NAME}_SOVERSION})
# exported includes are all under ${CMAKE_INSTALL_PREFIX}/include
target_include_directories(${PROJECT_NAME} INTERFACE "$<INSTALL_INTERFACE:include>")
target_link_libraries(${PROJECT_NAME} PUBLIC ChimeraTK::ChimeraTK-ApplicationCore
                                      PUBLIC ${Boost_LIBRARIES})


# do not remove runtime path of the library when installing
set_property(TARGET ${PROJECT_NAME} PROPERTY INSTALL_RPATH_USE_LINK_PATH TRUE)

# add a target to generate API documentation with Doxygen
include(cmake/enable_doxygen_documentation.cmake)

# enable coding style test
include(cmake/enable_code_style_check.cmake)

# Install the library and the executables
# this defines architecture-dependent ${CMAKE_INSTALL_LIBDIR}
include(GNUInstallDirs)
install( TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}Targets 
                                 LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} )

# all include files go into include/PROJECT_NAME
# The exclusion of ${PROJECT_NAME} prevents the recursive installation of the files just being installed.
# The original headers are in include/*.h, the installed ones in include/PROJECT_NAME/*.h.
install(DIRECTORY ${${PROJECT_NAME}_INCLUDE_DIRS} DESTINATION include/ChimeraTK/ApplicationCore
                                                  FILES_MATCHING PATTERN "*.h"
                                                                 PATTERN ".svn" EXCLUDE
                                                                 PATTERN "${PROJECT_NAME}" EXCLUDE)

list(APPEND ${PROJECT_NAME}_PUBLIC_DEPENDENCIES "ChimeraTK-ApplicationCore")
# we support our cmake EXPORTS as imported targets
set(PROVIDES_EXPORTED_TARGETS 1)
include(${CMAKE_SOURCE_DIR}/cmake/create_cmake_config_files.cmake)