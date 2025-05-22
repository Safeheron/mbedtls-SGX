#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sgx_urts.h"

#include "Enclave_u.h"

#if defined(_MSC_VER)
#define TOKEN_FILENAME   "Enclave.token"
#define ENCLAVE_FILENAME "Enclave.signed.dll"
#elif defined(__GNUC__)
#define TOKEN_FILENAME   "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"
#endif

int SGX_CDECL main(int argc, char* argv[]) {
    int ret = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_enclave_id_t enclave_id;

    printf("Try to create testing enclave ...\n");
    sgx_status = sgx_create_enclave(ENCLAVE_FILENAME, 0, nullptr, nullptr, &enclave_id, nullptr);
    if (sgx_status != SGX_SUCCESS) {
        printf("--->Initialize enclave failed! enclave file: %s, sgx message: %s\n", argv[1],
               strerror((int)sgx_status));
        return -1;
    }
    printf("Enclave is created!\n\n");


    printf("Enclave %lu created\n", enclave_id);
    sgx_status_t ecall_ret = ecall_c2_server(enclave_id, &ret);
    if (sgx_status != SGX_SUCCESS || ret != 0) {
        printf("\necall failed!\n");
        return -1;
    }

    printf("\nExit from function ecall_run()!\n");
    return ret;
}