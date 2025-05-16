#include "Enclave_t.h"
#include "ssl_client1.h"
//#include "enc.h"
//#include "s_server.h"
//#include "Log.h"
//#include "ssl_conn_hdlr.h"
#include "ssl_server/ssl_client_2.h"
#include "ssl_server/ssl_server_2.h"

#ifdef __cplusplus
extern "C" {
#endif

int sgx_connect();
int ecall_ssl_client_2();
int ecall_ssl_server_2();
int sgx_accept();
void ssl_conn_init();
void ssl_conn_teardown();
//void ssl_conn_handle(long int thread_id, thread_info_t *thread_info);

#ifdef __cplusplus
}
#endif

int sgx_connect()
{
    return ssl_client1();
}

int ecall_ssl_client_2(){
    return ssl_client_2_main();
}

int ecall_ssl_server_2(){
    return ssl_server_2_main();
}

int sgx_accept()
{
//    return ssl_server();
    return 0;
}

//TLSConnectionHandler* connectionHandler;

void ssl_conn_init(void) {
//  connectionHandler = new TLSConnectionHandler();
}

//void ssl_conn_handle(long int thread_id, thread_info_t* thread_info) {
//  connectionHandler->handle(thread_id, thread_info);
//}

void ssl_conn_teardown(void) {
//  delete connectionHandler;
}