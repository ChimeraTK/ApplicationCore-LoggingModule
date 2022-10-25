FIND_PACKAGE(Boost COMPONENTS unit_test_framework REQUIRED)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/executable_src testExecutables)
foreach( testExecutableSrcFile ${testExecutables})
  #NAME_WE means the base name without path and (longest) extension
  get_filename_component(executableName ${testExecutableSrcFile} NAME_WE)
  add_executable(${executableName} ${testExecutableSrcFile} ${test_headers})
  # do not link against the boost unit test library, the tests are not written for it!
  target_link_libraries(${executableName} ${PROJECT_NAME} ${ChimeraTK-ApplicationCore_LIBRARIES} ${HDF5_LIBRARIES})
  set_target_properties(${executableName} PROPERTIES LINK_FLAGS "-Wl,-rpath,${PROJECT_BINARY_DIR} ${Boost_LINK_FLAGS} ${ChimeraTK-ApplicationCore_LINK_FLAGS}")
  add_test(${executableName} ${executableName})
endforeach( testExecutableSrcFile )
