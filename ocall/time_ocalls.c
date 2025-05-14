#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <string.h>

void ocall_mbedtls_time(int64_t *unix_time)
{
    if (unix_time)
        *unix_time = (int64_t)time(NULL);
}

void ocall_mbedtls_time_ms(uint64_t *millis)
{
    if (!millis) return;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    *millis = (uint64_t)(tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL);
}

void ocall_mbedtls_gmtime_r(int64_t *unix_time, struct tm *result)
{
    if (!unix_time || !result) return;

    time_t time_value = (time_t)(*unix_time);

    if (gmtime_r(&time_value, result) == NULL) {
        memset(result, 0, sizeof(struct tm));
    }
}

