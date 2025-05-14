#ifndef MBEDTLS_SGX_TIME_H
#define MBEDTLS_SGX_TIME_H

#include "mbedtls/platform_time.h"

mbedtls_time_t mbedtls_sgx_time(mbedtls_time_t *time);

// Defined by mbedtls elsewhere
// mbedtls_ms_time_t mbedtls_ms_time(void);

// Defined by mbedtls elsewhere
// struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt, struct tm *tm_buf);

#endif //MBEDTLS_SGX_TIME_H
