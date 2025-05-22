set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++17")

set(CASE_1_CLIENT_SRC_FILES Enclave_u.c c1_client_host.cpp)
set(CASE_2_CLIENT_SRC_FILES Enclave_u.c c2_client_host.cpp)
set(CASE_2_SERVER_SRC_FILES Enclave_u.c c2_server_host.cpp)

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

add_executable(c1_client ${CASE_1_CLIENT_SRC_FILES})
add_executable(c2_client ${CASE_2_CLIENT_SRC_FILES})
add_executable(c2_server ${CASE_2_SERVER_SRC_FILES})

include_directories(
        ${SGXSDK_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(c1_client
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${MBEDTLS_SGX_LIB_U} -lpthread)

target_link_libraries(c2_client
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${MBEDTLS_SGX_LIB_U} -lpthread)

target_link_libraries(c2_server
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${MBEDTLS_SGX_LIB_U} -lpthread)

add_dependencies(c1_client enclave)
add_dependencies(c2_client enclave)
add_dependencies(c2_server enclave)