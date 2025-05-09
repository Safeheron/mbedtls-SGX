#include "Enclave_t.h"
#include "ssl_client1.h"
//#include "enc.h"
//#include "s_server.h"
//#include "Log.h"
//#include "ssl_conn_hdlr.h"

#ifdef __cplusplus
extern "C" {
#endif

int sgx_connect();
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