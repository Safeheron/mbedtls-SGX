#include <stdio.h>
#include <stdlib.h>

int ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    int ret = printf("%s", str);
    fflush(stdout);
    return ret;
}

void ocall_mbedtls_exit(int exit_code) {
//    printf("Enclave requested exit with code: %d\n", exit_code);
    exit(exit_code);
}