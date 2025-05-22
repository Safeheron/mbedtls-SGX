// mbedtls_https_client.c - Multi-threaded HTTPS client using Mbed TLS

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "c2_ssl_client.h"

#include "mbedtls/platform.h"

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT "4433"
#define NUM_CLIENTS 5
#define DEBUG_LEVEL 4

// Server RSA Certificate
const char REMOTE_PEM_SERVER_CERT[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDrTCCApWgAwIBAgIUcB/OrWlYyLt4nBXmPd4yrKSSwmIwDQYJKoZIhvcNAQEL\r\n"
"BQAwZjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0Jl\r\n"
"aWppbmcxDjAMBgNVBAoMBU15T3JnMQ8wDQYDVQQLDAZNeURlcHQxEjAQBgNVBAMM\r\n"
"CWxvY2FsaG9zdDAeFw0yNTA1MTUwODM3MjhaFw0yNjA1MTUwODM3MjhaMGYxCzAJ\r\n"
"BgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMQ4w\r\n"
"DAYDVQQKDAVNeU9yZzEPMA0GA1UECwwGTXlEZXB0MRIwEAYDVQQDDAlsb2NhbGhv\r\n"
"c3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtAOjZMaKhQbD9BAr6\r\n"
"I3SvXIlyQ5xZxoOV5bnOvcIXq0JzwNZFDou4HChhL0Ajnt+hBXf5+zZOBo/dw6Ti\r\n"
"0C3j0WwoMohk3rOlcrDam6OdnxOlKXdYGvexGwh+OshAn9A3MBPjonDoJUO+qHXg\r\n"
"rmjQs6cVcRlcIXbRRaJZlRTtNuzF66kB/HJ939PJNgxm9WslJJebBjSdHcfLFWPU\r\n"
"krtT3KaXnpAEkjvMzD+4Ar5oLHvYukIWvBCpZnIvJ4KMMT965kroXztCfciyxRjI\r\n"
"7nkGTEjTRUm4HvD8Tjqy1Vk1fNoblQtgigKMtD1JB5SzwhHV+QSN9nQycvp2LNBz\r\n"
"eOXvAgMBAAGjUzBRMB0GA1UdDgQWBBRh28oMY9CVVZuAiNJtMAUc9EQZdDAfBgNV\r\n"
"HSMEGDAWgBRh28oMY9CVVZuAiNJtMAUc9EQZdDAPBgNVHRMBAf8EBTADAQH/MA0G\r\n"
"CSqGSIb3DQEBCwUAA4IBAQAv8LUTjiTq5tlezOUZ8PMezYQW0wu+lzXxHhtvmY54\r\n"
"E3gfOMvLkj77ReKAV0xIeMWBHZWvz4t4OoQfAH02dw4/zY3PuG/72wA90ZOSS0l2\r\n"
"3No0LbbgmB4NCEMXAhLURTlBUqsra2vfKaDLzu/pRhrvodJpMrc/gfQ4zeUbeTRo\r\n"
"/UFIKuk0UTBhKYv0E/Am7NG9MIfU2Z2jj8MbDxXY9JbbmA4oThod8dTbEuGpjX6P\r\n"
"qt8MhqJylRWwWCAl/XWn3BqwdObD+LIq8fQhRWVEyO1SDtNV/ZvZbRhnCgd7k2xO\r\n"
"etvgxJu1zLcUD91qJYY8VnofA2xwrPCor8zKe1/uIfof\r\n"
"-----END CERTIFICATE-----\r\n";
const size_t REMOTE_PEM_SERVER_CERT_LEN = sizeof(REMOTE_PEM_SERVER_CERT);

void print_mbedtls_error(const char *msg, int err)
{
    char err_buf[256];
    mbedtls_strerror(err, err_buf, sizeof(err_buf));
    mbedtls_printf("%s: -0x%04X - %s\n", msg, -err, err_buf);
}

void *client_thread(void *arg)
{
    int ret;
    int client_id = *(int *)arg;
    char buf[4096];

    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_x509_crt trusted_cert;
    mbedtls_x509_crt_init(&trusted_cert);

    const int *ciphersuites = mbedtls_ssl_list_ciphersuites();
    while (*ciphersuites) {
        mbedtls_printf("Support: %s\n", mbedtls_ssl_get_ciphersuite_name(*ciphersuites));
        ciphersuites++;
    }

    const char *pers = "mbedtls_client";

    mbedtls_net_init_ocall(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0) {
        print_mbedtls_error("mbedtls_ctr_drbg_seed", ret);
        goto exit;
    }

    if ((ret = mbedtls_net_connect_ocall(&server_fd, SERVER_HOST, SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        print_mbedtls_error("mbedtls_net_connect_ocall", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
        goto exit;
    }


    // 加载服务端的 PEM 证书
    mbedtls_x509_crt_parse(&trusted_cert,
                           (const unsigned char *)REMOTE_PEM_SERVER_CERT,
                           strlen(REMOTE_PEM_SERVER_CERT) + 1);

    // 配置为客户端信任的根 CA
    mbedtls_ssl_conf_ca_chain(&conf, &trusted_cert, NULL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        print_mbedtls_error("mbedtls_ssl_setup", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send_ocall, mbedtls_net_recv_ocall, NULL);

    if ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        print_mbedtls_error("mbedtls_ssl_handshake", ret);
        goto exit;
    }

    const char *http_request = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)http_request, strlen(http_request))) < 0) {
        print_mbedtls_error("mbedtls_ssl_write", ret);
        goto exit;
    }

    memset(buf, 0, sizeof(buf));
    if ((ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, sizeof(buf)-1)) < 0) {
        print_mbedtls_error("mbedtls_ssl_read", ret);
        goto exit;
    }

    mbedtls_printf("[Client %d] Received:\n%s\n", client_id, buf);

exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free_ocall(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    free(arg);
    return NULL;
}

int c2_ssl_client_main(void)
{
    pthread_t threads[NUM_CLIENTS];
    for (int i = 0; i < NUM_CLIENTS; ++i) {
        int *client_id = malloc(sizeof(int));
        *client_id = i;
        if (pthread_create(&threads[i], NULL, client_thread, client_id) != 0) {
            mbedtls_printf("pthread_create");
            free(client_id);
        }
    }
    for (int i = 0; i < NUM_CLIENTS; ++i) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}
