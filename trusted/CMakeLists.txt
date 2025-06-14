FILE(GLOB MBEDTLS_SGX_SRC_FILES mbedtls-${MBEDTLS_VERSION}/library/*.c)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}_t.c
    COMMAND ${SGX_EDGER8R} --trusted ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.edl
    --search-path ${SGX_SDK}/include
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(${PROJECT_NAME}_t STATIC ${MBEDTLS_SGX_SRC_FILES} ${PROJECT_NAME}_t.c glue.c dummy.c net_sockets_proxy.c
        sgx_time_imp.c)

# add_subdirectory(mbedtls-${MBEDTLS_VERSION}/include)

include_directories(
    $(CMAKE_CURRENT_SOURCE_DIR)
    mbedtls-${MBEDTLS_VERSION}/include
    ${SGX_SDK}/include
    ${SGX_SDK}/include/tlibc
    ${SGX_SDK}/include/libcxx
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -nostdinc -fvisibility=hidden -fpie -fstack-protector")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++03 -nostdinc++")

target_link_options(${PROJECT_NAME}_t PRIVATE ${SGX_COMMON_CFLAGS}
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH}
    -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive
    -Wl,--start-group ${LIB_MBEDTLS_PATH} -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic
    -Wl,--defsym,__ImageBase=0)

# install(TARGETS ${PROJECT_NAME}_t
#     DESTINATION lib
#     PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
#
# install(FILES ${PROJECT_NAME}.edl
#     DESTINATION lib
#     PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)