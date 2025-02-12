include(CMakePackageConfigHelpers)

set(exported_targets_name "${PROJECT_NAME}Targets")
set(exported_targets_filename "${exported_targets_name}.cmake")
set(export_dirpath "lib/cmake/${PROJECT_NAME}")
set(config_basename "${PROJECT_NAME}Config")
set(config_filename "${config_basename}.cmake")
set(version_filename "${config_basename}Version.cmake")
set(MBEDTLS_SOURCE_PATH "${CMAKE_SOURCE_DIR}")

write_basic_package_version_file(
        ${version_filename}
        COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
        "cmake/${config_filename}.in" "${config_filename}"
        INSTALL_DESTINATION "${export_dirpath}"
)

# install trusted library file
install(
        TARGETS ${PROJECT_NAME}_t
        EXPORT ${exported_targets_name}
        ARCHIVE DESTINATION lib
)

# install untrusted library file
install(
        TARGETS ${PROJECT_NAME}_u
        EXPORT ${exported_targets_name}
        ARCHIVE DESTINATION lib
)

install(
        EXPORT ${exported_targets_name}
        FILE ${exported_targets_filename}
        DESTINATION ${export_dirpath}
)

install(
        FILES
        "${CMAKE_CURRENT_BINARY_DIR}/${config_filename}"
        "${CMAKE_CURRENT_BINARY_DIR}/${version_filename}"
        DESTINATION
        ${export_dirpath}
)

# Install header files
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/mbedtls/
        DESTINATION include/mbedtls_SGX
        FILES_MATCHING PATTERN "*.h"
        )
install(FILES ${CMAKE_SOURCE_DIR}/include/glue.h
        DESTINATION include/mbedtls_SGX
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
        )

# Install EDL file
install(FILES ${CMAKE_SOURCE_DIR}/trusted/${PROJECT_NAME}.install.edl
        DESTINATION include/mbedtls_SGX
        RENAME ${PROJECT_NAME}.edl
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
        )
