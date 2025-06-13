# need 3.0 for multiple line strings
cmake_minimum_required(VERSION 3.0)
project(mbedtls_SGX "C" "CXX")

set(PROJECT_VERSION 3.6.3)
set(MBEDTLS_VERSION 3.6.3)

set(SGX_SDK /opt/intel/sgxsdk)
set(SGX_ARCH x64)
set(SGX_MODE HW CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
set(COMPILE_EXAMPLES NO CACHE BOOL "Build examples")
set(SGX_BUILD RELEASE CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")

include (cmake/Init.cmake)
include (cmake/ConfigSGX.cmake)

# set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/${PROJECT_NAME}-${MBEDTLS_VERSION})

add_subdirectory(trusted)
add_subdirectory(ocall)

if (COMPILE_EXAMPLES)
    add_subdirectory(example)
endif()

include("cmake/setup_installation.cmake")