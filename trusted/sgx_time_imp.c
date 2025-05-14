#include "sgx_time_imp.h"
#include "mbedtls_SGX_t.h"

mbedtls_time_t mbedtls_sgx_time(mbedtls_time_t *t){
    int64_t now = 0;
    ocall_mbedtls_time(&now);
    if (t) *t = now;
    return now;
}

mbedtls_ms_time_t mbedtls_ms_time(void) {
    uint64_t ms = 0;
    ocall_mbedtls_time_ms(&ms);
    return ms;
}

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt,
                                     struct tm *tm_buf) {
    if (!tt || !tm_buf) return NULL;
    int64_t t = (int64_t)(*tt);
    ocall_mbedtls_gmtime_r(&t, tm_buf);
    return tm_buf;
}