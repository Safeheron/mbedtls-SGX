set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++17")

set(CLIENT_SRC_FILES Enclave_u.c host.cpp)
set(HTTPS_CLIENT_2_SRC_FILES Enclave_u.c https_client_2_host.cpp)
set(HTTPS_SERVER_2_SRC_FILES Enclave_u.c https_server_2_host.cpp)

set_directory_properties(PROPERTIES
        ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c
        COMMAND ${SGX_EDGER8R} --untrusted Enclave.edl
        --search-path ../enclave/ # enclave.edl
        --search-path ${SGX_SDK}/include
        --search-path ${CMAKE_SOURCE_DIR}/trusted # mbedtls_sgx.edl
        COMMENT "Generating Enclave_u.{c,h}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(s_client ${CLIENT_SRC_FILES})
add_executable(http_client_2 ${HTTPS_CLIENT_2_SRC_FILES})
add_executable(http_server_2 ${HTTPS_SERVER_2_SRC_FILES})

include_directories(
        ${SGXSDK_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(s_client
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${MBEDTLS_SGX_LIB_U} -lpthread)

target_link_libraries(http_client_2
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${MBEDTLS_SGX_LIB_U} -lpthread)

target_link_libraries(http_server_2
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${MBEDTLS_SGX_LIB_U} -lpthread)

#target_link_libraries(s_server
#        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
#        ${MBEDTLS_SGX_LIB_U} -lpthread)
#
#target_link_libraries(m_server
#        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
#        ${MBEDTLS_SGX_LIB_U} -lpthread)

add_dependencies(s_client enclave)
add_dependencies(http_client_2 enclave)
add_dependencies(http_server_2 enclave)