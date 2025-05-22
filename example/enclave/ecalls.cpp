#include "Enclave_t.h"
#include "case_1/c1_ssl_client.h"
#include "case_2/c2_ssl_client.h"
#include "case_2/c2_ssl_server.h"

#ifdef __cplusplus
extern "C" {
#endif

int ecall_c1_client();
int ecall_c2_client();
int ecall_c2_server();

#ifdef __cplusplus
}
#endif

int ecall_c1_client()
{
    return c1_ssl_client_main();
}

int ecall_c2_client(){
    return c2_ssl_client_main();
}

int ecall_c2_server(){
    return c2_ssl_server_main();
}