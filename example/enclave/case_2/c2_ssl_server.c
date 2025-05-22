#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf
#define mbedtls_time_t          time_t
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#define mbedtls_calloc          calloc
#define mbedtls_free            free
#endif /* MBEDTLS_PLATFORM_C */

//#if !defined(MBEDTLS_ENTROPY_C) || \
//    !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_X509_CRT_PARSE_C) || \
//    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_SRV_C) || \
//    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_PEM_PARSE_C) || \
//    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_PK_PARSE_C) || \
//    !defined(MBEDTLS_TIMING_C)
#if !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_X509_CRT_PARSE_C) || \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_SRV_C) || \
    !defined(MBEDTLS_PEM_PARSE_C) || \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_PK_PARSE_C)
int main_disabled_due_to_config(void) {
    mbedtls_printf("Required Mbed TLS modules not defined in config.h.\n");
    mbedtls_exit(MBEDTLS_EXIT_FAILURE);
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h" // For mbedtls_x509_crt
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/pk.h"       // For mbedtls_pk_context

#include <string.h>
#include <stdio.h>
#include <pthread.h>
// #include <signal.h>
#include <unistd.h> // For close()

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#include "c2_ssl_server.h"

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>Mbed TLS Test Server (Thread Pool)</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n" \
    "<p>Handled by worker thread: %lu</p>\r\n"

#define DEBUG_LEVEL 0
#define LISTEN_PORT "4433"

#define NUM_WORKER_THREADS 4
#define TASK_QUEUE_SIZE 16

// --- Hardcoded RSA Certificate and Key (PEM format) ---
// These are standard Mbed TLS test certificates for "localhost" / "mbed TLS Test Server"
// In a real application, USE YOUR OWN CERTIFICATES!

// Server RSA Certificate
const char PEM_SERVER_CERT[] =
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
const size_t PEM_SERVER_CERT_LEN = sizeof(PEM_SERVER_CERT);

// Server RSA Private Key
const char PEM_SERVER_KEY[] =
"-----BEGIN PRIVATE KEY-----\r\n"
"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCtAOjZMaKhQbD9\r\n"
"BAr6I3SvXIlyQ5xZxoOV5bnOvcIXq0JzwNZFDou4HChhL0Ajnt+hBXf5+zZOBo/d\r\n"
"w6Ti0C3j0WwoMohk3rOlcrDam6OdnxOlKXdYGvexGwh+OshAn9A3MBPjonDoJUO+\r\n"
"qHXgrmjQs6cVcRlcIXbRRaJZlRTtNuzF66kB/HJ939PJNgxm9WslJJebBjSdHcfL\r\n"
"FWPUkrtT3KaXnpAEkjvMzD+4Ar5oLHvYukIWvBCpZnIvJ4KMMT965kroXztCfciy\r\n"
"xRjI7nkGTEjTRUm4HvD8Tjqy1Vk1fNoblQtgigKMtD1JB5SzwhHV+QSN9nQycvp2\r\n"
"LNBzeOXvAgMBAAECggEAP93wGA5s3V8k+aL+cm2YbAybaSVwmOviM/pE5//BoX9F\r\n"
"3vm3oHLIPcWXWplY8k16fTVJn22QFKnzfoj1XA5CgrITXZuaIrLcWx3GEE4Yzt2l\r\n"
"IPn35vy9qBI0xnTo7IKTGWyUSxry16C6K66BJdr9Mt6/tfi0xgBMnuE4GB4jRZa/\r\n"
"zN/s56vPNGcggdTsE6fgjQ6mVbqt0i3X7um/JlnXU8dwUxnRZpYBz6piJmb/R6Pm\r\n"
"RsfECh3pEsHT1byoOanNXpXmlufQATwMJYe2euWabDeY/O+ISy8dPIuK6aOUlu9a\r\n"
"wPLw/EI2ZZkC2u3CEphV2aWHEU+pNo+9L1wDFgQOQQKBgQDYUwts3TMjUPs5z15l\r\n"
"H0hzr0AWrMtK0d5ujMFpzzydjKmeDF2xZnocLDIQ2PqaNvcotX5mH/LtUFNCWOHO\r\n"
"5YkXXCr0/DOQfKhAM3tm6LM46YUCH+CCYbIo73cMR1mDLcHmeGnEDwYWFeezO7iK\r\n"
"snlHe6gyMYedp0am4vDRWJ95XwKBgQDMu9ipQrkyDcfqvgBkS5dWLEcKppBfC4VU\r\n"
"v8KHFmdjXRrSmHpyY7FQIn6GpN2hNlEs2Q9C+7IkrJJdqG35VcDSLQuSDqPA2ulD\r\n"
"Un0j5EsxXT0NeOqzoMDKjQiJmHgxmAlRoxEEU77wNjfOV+DLUZHWgAiQ8Io81vdh\r\n"
"kqvl26WNcQKBgQCVPS2LrEskWTEIn/xybROR49ymCA20D3eR8v9YXQVnd+xowgU9\r\n"
"ZwJlP0RHBTpWfAcliZirIe15NUpLYoBeOVLLz+U+4GM+khGNQTcoNu+2GryNS6qa\r\n"
"qIW94f7SdMLXUhEMTBRDk03SnMgdidz1qs0quK+/+RWjeQywA6657pcOpwKBgQCA\r\n"
"CbJ0GHBtp0Sxv+XK06Nvlv1O4eBEMJZP7CUiCpbaA2406nsZctN/RDNQzWZ13dxi\r\n"
"adUrlPFSEkLvI9izKDgQuW8VBubOQ5nCKqJsgeeslZ0LAeX2NMCdbBo8wwfYLDcX\r\n"
"wR1xUVaGL8Iy366MORU1ypiQ3H33kpDfirTKadVdYQKBgQC93TPUHWV+ifl/x93m\r\n"
"weYlbC/2ZIN7cK3bYG4H/muNoDgtmt707DS2HaGj9vBaqwfEZTgBpRj7+UJ7RqVG\r\n"
"2i02FR2LZH5Ouju2peheyagINE2nct7ecI0utN5Cwk6p4Oo8MaYzPsKw+4+9XDA/\r\n"
"9AX3sblI+YZiPWEIV4gr966btw==\r\n"
"-----END PRIVATE KEY-----\r\n";
const size_t PEM_SERVER_KEY_LEN = sizeof(PEM_SERVER_KEY);

// --- Thread Pool Structures ---
typedef struct {
    int client_fd;
    char client_ip[16];
} task_t;

typedef struct {
    pthread_t *threads;
    int num_threads;

    task_t *task_queue;
    int queue_capacity;
    int queue_front;
    int queue_rear;
    int task_count;

    pthread_mutex_t mutex;
    pthread_cond_t cond_task_available; // Worker waits on this if queue is empty
    pthread_cond_t cond_slot_available; // Main thread waits on this if queue is full

    int shutdown_flag;
    mbedtls_ssl_config *shared_ssl_config;
} thread_pool_t;

// --- Global Variables ---
static int G_stop_server = 0;
static mbedtls_net_context G_listen_fd_ctx;
static thread_pool_t G_thread_pool;
static mbedtls_ssl_config G_ssl_config; // Global SSL config shared by threads
static mbedtls_entropy_context G_entropy;
static mbedtls_ctr_drbg_context G_ctr_drbg;
static mbedtls_x509_crt G_srvcert;
static mbedtls_pk_context G_pkey;

#if defined(MBEDTLS_SSL_CACHE_C)
static mbedtls_ssl_cache_context G_ssl_cache;
#endif

pthread_mutex_t stop_flag_lock;
void c2_stop_server(void) {
    pthread_mutex_lock(&stop_flag_lock);
    G_stop_server = 1;
    pthread_mutex_unlock(&stop_flag_lock);
}
int c2_get_stop_flag(void) {
    int ret;
    pthread_mutex_lock(&stop_flag_lock);
    ret = G_stop_server;
    pthread_mutex_unlock(&stop_flag_lock);
    return ret;
}

// --- Mbed TLS Debug Function ---
static void my_debug_func(void *ctx, int level,
                          const char *file, int line,
                          const char *str) {
    ((void)level); // unused
    const char *p = file;
    while(*p != '\0') p++; // Find end of file string
    while(p > file && *p != '/' && *p != '\\') p--; // Find last component
    if(*p == '/' || *p == '\\') p++;

//    mbedtls_fprintf((FILE *)ctx, "%lu: %s:%04d: %s", (unsigned long)pthread_self(), p, line, str);
//    fflush((FILE *)ctx);
}

// --- Signal Handler ---
void sigint_term_handler(int sig) {
    (void)sig;
    G_stop_server = 1;
    mbedtls_printf("\nSignal %d received, initiating server shutdown...\n", sig);
    // Close listening socket to unblock accept()
    if (G_listen_fd_ctx.fd != -1) {
        // mbedtls_net_free_ocall will close the fd.
        // To avoid race if main is also trying to free, just close fd here.
        // Or better, let main loop handle it after stop_server is set.
        // Forcing accept to return:
//        close(G_listen_fd_ctx.fd); // Directly close, accept will fail.
        mbedtls_net_close_ocall(&G_listen_fd_ctx); // Directly close, accept will fail.
        G_listen_fd_ctx.fd = -1;     // Mark as closed
    }
}

// --- Client Connection Processing Function (called by worker threads) ---
void process_client_connection(task_t task, mbedtls_ssl_config *ssl_conf) {
    int ret, len;
    mbedtls_net_context client_net_ctx;
    mbedtls_ssl_context ssl;
    unsigned char buf[2048];
    pthread_t thread_id = pthread_self();

    mbedtls_net_init_ocall(&client_net_ctx);
    mbedtls_ssl_init(&ssl);

    client_net_ctx.fd = task.client_fd;

    mbedtls_printf("[%s] Worker %lu: Processing new connection.\n", task.client_ip, (unsigned long)thread_id);

    if ((ret = mbedtls_ssl_setup(&ssl, ssl_conf)) != 0) {
        mbedtls_printf( "[%s] Worker %lu: mbedtls_ssl_setup failed: -0x%04x\n", task.client_ip, (unsigned long)thread_id, (unsigned int)-ret);
        goto cleanup;
    }

    mbedtls_ssl_set_bio(&ssl, &client_net_ctx, mbedtls_net_send_ocall, mbedtls_net_recv_ocall, NULL);

    mbedtls_printf("[%s] Worker %lu: Performing SSL/TLS handshake...\n", task.client_ip, (unsigned long)thread_id);
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf( "[%s] Worker %lu: mbedtls_ssl_handshake failed: -0x%04x\n", task.client_ip, (unsigned long)thread_id, (unsigned int)-ret);
            goto cleanup;
        }
    }
    mbedtls_printf("[%s] Worker %lu: Handshake successful. Cipher: %s\n", task.client_ip, (unsigned long)thread_id, mbedtls_ssl_get_ciphersuite(&ssl));

    mbedtls_printf("[%s] Worker %lu: Reading HTTP request...\n", task.client_ip, (unsigned long)thread_id);
    memset(buf, 0, sizeof(buf));
    // Set a read timeout (optional, but good practice)
    // mbedtls_ssl_conf_read_timeout(&conf, 5000); // Example: 5 seconds, set on global conf or per-ssl context
    ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        mbedtls_printf( "[%s] Worker %lu: mbedtls_ssl_read incomplete.\n", task.client_ip, (unsigned long)thread_id);
        goto cleanup;
    }
    if (ret <= 0) {
        // Handle read errors
        goto cleanup;
    }
    mbedtls_printf("[%s] Worker %lu: Received %d bytes:\n%s\n", task.client_ip, (unsigned long)thread_id, ret, (char *)buf);

    mbedtls_printf("[%s] Worker %lu: Sending HTTP response...\n", task.client_ip, (unsigned long)thread_id);
    len = snprintf((char *)buf, sizeof(buf), HTTP_RESPONSE, mbedtls_ssl_get_ciphersuite(&ssl), (unsigned long)thread_id);

    ret = mbedtls_ssl_write(&ssl, buf, len);
    if (ret < 0) {
         mbedtls_printf( "[%s] Worker %lu: mbedtls_ssl_write failed: -0x%04x\n", task.client_ip, (unsigned long)thread_id, (unsigned int)-ret);
    } else {
        mbedtls_printf("[%s] Worker %lu: Sent %d bytes of HTTP response.\n", task.client_ip, (unsigned long)thread_id, ret);
    }

cleanup:
    mbedtls_printf("[%s] Worker %lu: Closing connection.\n", task.client_ip, (unsigned long)thread_id);
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free_ocall(&client_net_ctx); // This closes task.client_fd
    mbedtls_ssl_free(&ssl);
    mbedtls_printf("[%s] Worker %lu: Connection processed and closed.\n", task.client_ip, (unsigned long)thread_id);
}

// --- Thread Pool Worker Function ---
static void *worker_thread_main(void *arg) {
    thread_pool_t *pool = (thread_pool_t *)arg;
    task_t task;

    while (1) {
        pthread_mutex_lock(&pool->mutex);

        while (pool->task_count == 0 && !pool->shutdown_flag) {
            pthread_cond_wait(&pool->cond_task_available, &pool->mutex);
        }

        if (pool->shutdown_flag && pool->task_count == 0) {
            pthread_mutex_unlock(&pool->mutex);
            break; // Exit loop if shutdown and no more tasks
        }

        // Dequeue task
        task = pool->task_queue[pool->queue_front];
        pool->queue_front = (pool->queue_front + 1) % pool->queue_capacity;
        pool->task_count--;

        pthread_cond_signal(&pool->cond_slot_available); // Signal that a slot is now free
        pthread_mutex_unlock(&pool->mutex);

        process_client_connection(task, pool->shared_ssl_config);
    }
    mbedtls_printf("Worker %lu: Exiting.\n", (unsigned long)pthread_self());
    pthread_exit(NULL);
}

// --- Thread Pool Functions ---
void thread_pool_shutdown(thread_pool_t *pool);
int thread_pool_init(thread_pool_t *pool, int num_threads, int queue_capacity, mbedtls_ssl_config *ssl_conf) {
    pool->num_threads = num_threads;
    pool->queue_capacity = queue_capacity;
    pool->queue_front = 0;
    pool->queue_rear = 0;
    pool->task_count = 0;
    pool->shutdown_flag = 0;
    pool->shared_ssl_config = ssl_conf;

    pool->threads = (pthread_t *)mbedtls_calloc(num_threads, sizeof(pthread_t));
    if (!pool->threads) {
        mbedtls_printf("Failed to allocate memory for threads");
        return -1;
    }

    pool->task_queue = (task_t *)mbedtls_calloc(queue_capacity, sizeof(task_t));
    if (!pool->task_queue) {
        mbedtls_printf("Failed to allocate memory for task queue");
        mbedtls_free(pool->threads);
        return -1;
    }

    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->cond_task_available, NULL);
    pthread_cond_init(&pool->cond_slot_available, NULL);

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_thread_main, pool) != 0) {
            mbedtls_printf("Failed to create worker thread");
            // Cleanup already created threads and resources
            pool->num_threads = i; // Only join created threads
            thread_pool_shutdown(pool); // Attempt to clean up what was made
            return -1;
        }
    }
    mbedtls_printf("Thread pool initialized with %d workers.\n", num_threads);
    return 0;
}

int thread_pool_add_task(thread_pool_t *pool, mbedtls_net_context *client_ctx, const char *client_ip) {
    pthread_mutex_lock(&pool->mutex);

    while (pool->task_count == pool->queue_capacity && !pool->shutdown_flag) {
        mbedtls_printf("Task queue full. Main thread waiting for a slot...\n");
        pthread_cond_wait(&pool->cond_slot_available, &pool->mutex);
    }

    if (pool->shutdown_flag) {
        pthread_mutex_unlock(&pool->mutex);
        mbedtls_net_close_ocall(client_ctx); // Don't add task if shutting down
        return -1;
    }

    pool->task_queue[pool->queue_rear].client_fd = client_ctx->fd;
    strncpy(pool->task_queue[pool->queue_rear].client_ip, client_ip, sizeof(pool->task_queue[0].client_ip) -1);
    pool->task_queue[pool->queue_rear].client_ip[sizeof(pool->task_queue[0].client_ip)-1] = '\0';

    pool->queue_rear = (pool->queue_rear + 1) % pool->queue_capacity;
    pool->task_count++;

    pthread_cond_signal(&pool->cond_task_available);
    pthread_mutex_unlock(&pool->mutex);
    return 0;
}

void thread_pool_shutdown(thread_pool_t *pool) {
    mbedtls_printf("Initiating thread pool shutdown sequence...\n");
    pthread_mutex_lock(&pool->mutex);
    pool->shutdown_flag = 1;
    pthread_mutex_unlock(&pool->mutex);

    // Wake up all worker threads so they can check the shutdown_flag
    pthread_cond_broadcast(&pool->cond_task_available);
    // Wake up main thread if it's waiting for a slot (though it shouldn't be if G_stop_server is also set)
    pthread_cond_broadcast(&pool->cond_slot_available);


    for (int i = 0; i < pool->num_threads; i++) {
        if (pthread_join(pool->threads[i], NULL) != 0) {
            mbedtls_printf("Failed to join thread\n");
        } else {
            mbedtls_printf("Joined worker thread %d.\n", i);
        }
    }

    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->cond_task_available);
    pthread_cond_destroy(&pool->cond_slot_available);

    mbedtls_free(pool->threads);
    mbedtls_free(pool->task_queue);
    mbedtls_printf("Thread pool shutdown complete.\n");
}


// --- Main Server Function ---
int c2_ssl_server_main(void) {
    int ret = 1; // Default to failure
    const char *pers = "https_server_threadpool";
    char client_ip_str[16];
    size_t client_ip_len;
    mbedtls_net_context client_loop_ctx; // For accept loop

    if (pthread_mutex_init(&stop_flag_lock, NULL) != 0) {
        mbedtls_printf("mutex (stop_flag_lock) init failed");
        return 1;
    }

    const int *ciphersuites = mbedtls_ssl_list_ciphersuites();
    while (*ciphersuites) {
        //printf("Support: %s\n", mbedtls_ssl_get_ciphersuite_name(*ciphersuites));
        mbedtls_printf("Support: %s\n", mbedtls_ssl_get_ciphersuite_name(*ciphersuites));
        ciphersuites++;
    }

    mbedtls_net_init_ocall(&G_listen_fd_ctx);
    mbedtls_net_init_ocall(&client_loop_ctx);
    mbedtls_ssl_config_init(&G_ssl_config);
    mbedtls_x509_crt_init(&G_srvcert);
    mbedtls_pk_init(&G_pkey);
    mbedtls_entropy_init(&G_entropy);
    mbedtls_ctr_drbg_init(&G_ctr_drbg);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&G_ssl_cache);
#endif
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

//    signal(SIGINT, sigint_term_handler);
//    signal(SIGTERM, sigint_term_handler);

    mbedtls_printf("\n  . Seeding the random number generator...");
    if ((ret = mbedtls_ctr_drbg_seed(&G_ctr_drbg, mbedtls_entropy_func, &G_entropy,
                               (const unsigned char *)pers, strlen(pers))) != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int)-ret);
        goto exit_main_cleanup;
    }
    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Loading server certificate...");
    ret = mbedtls_x509_crt_parse(&G_srvcert, (const unsigned char *)PEM_SERVER_CERT, PEM_SERVER_CERT_LEN);
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_x509_crt_parse returned -0x%04x\n", (unsigned int)-ret);
        goto exit_main_cleanup;
    }
    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Loading server private key...");
    ret = mbedtls_pk_parse_key(&G_pkey, (const unsigned char *)PEM_SERVER_KEY, PEM_SERVER_KEY_LEN, NULL, 0, mbedtls_ctr_drbg_random, &G_ctr_drbg);
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_pk_parse_key returned -0x%04x\n", (unsigned int)-ret);
        goto exit_main_cleanup;
    }
    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up SSL/TLS data...");
    if ((ret = mbedtls_ssl_config_defaults(&G_ssl_config,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned -0x%04x\n", (unsigned int)-ret);
        goto exit_main_cleanup;
    }
    mbedtls_ssl_conf_rng(&G_ssl_config, mbedtls_ctr_drbg_random, &G_ctr_drbg);
//    mbedtls_ssl_conf_dbg(&G_ssl_config, my_debug_func, stdout);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&G_ssl_config, &G_ssl_cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif
//    mbedtls_ssl_conf_ca_chain(&G_ssl_config, G_srvcert.next, NULL); // Using srvcert as its own CA for self-signed, or actual chain if provided
    if ((ret = mbedtls_ssl_conf_own_cert(&G_ssl_config, &G_srvcert, &G_pkey)) != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned -0x%04x\n", (unsigned int)-ret);
        goto exit_main_cleanup;
    }
    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Initializing thread pool...");
    if (thread_pool_init(&G_thread_pool, NUM_WORKER_THREADS, TASK_QUEUE_SIZE, &G_ssl_config) != 0) {
        mbedtls_printf( " failed\n  ! Thread pool initialization failed.\n");
        goto exit_main_cleanup; // thread_pool_init should clean up its partial creations
    }
    mbedtls_printf(" ok\n");


    mbedtls_printf("  . Binding to https://localhost:%s/ ...", LISTEN_PORT);
    if ((ret = mbedtls_net_bind_ocall(&G_listen_fd_ctx, NULL, LISTEN_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_net_bind_ocall returned -0x%04x\n", (unsigned int)-ret);
        goto exit_threadpool_shutdown;
    }
    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Waiting for client connections...\n");
    while (!G_stop_server) {
        mbedtls_net_init_ocall(&client_loop_ctx); // Re-initialize for each accept attempt
        ret = mbedtls_net_accept_ocall(&G_listen_fd_ctx, &client_loop_ctx,
                                 client_ip_str, sizeof(client_ip_str), &client_ip_len);

        if (G_stop_server) { // Check immediately after accept returns
            if (client_loop_ctx.fd != -1) mbedtls_net_close_ocall(&client_loop_ctx); // If a connection was accepted just before shutdown
            break;
        }

        if (ret == 0) {
            mbedtls_printf("  . Connection accepted from: %s\n", client_ip_str);
            if (thread_pool_add_task(&G_thread_pool, &client_loop_ctx, client_ip_str) != 0) {
                mbedtls_printf( "Failed to add task to pool (pool shutting down or error), closing connection.\n");
                // client_loop_ctx.fd was already closed by thread_pool_add_task if it failed due to shutdown
                // or mbedtls_net_free_ocall(&client_loop_ctx) would close it.
                // If it was not closed by add_task, we need to close it here.
                // The `client_loop_ctx.fd` ownership is tricky. Let `process_client_connection` (via net_free) always close.
                // If add_task fails (e.g. pool full and non-blocking, or shutting down), fd must be closed here.
                // The current `thread_pool_add_task` closes fd if pool is shutting down.
                // If it was full and blocked, then accept wouldn't have returned yet.
                // So, if add_task returns error, it implies fd was not queued, thus should be closed.
                // But client_loop_ctx.fd might be -1 if add_task closed it.
                // The simplest is: if thread_pool_add_task fails, fd is already closed by it (if due to shutdown)
                // or it needs to be closed if it failed for other reasons (e.g. hypothetical non-blocking full queue).
                // The current `thread_pool_add_task` closes if `pool->shutdown_flag` is set.
                // The socket `client_loop_ctx.fd` is now "owned" by the task if successfully added.
            } else {
                // client_loop_ctx.fd is now managed by the thread pool task.
                // Do not free/close client_loop_ctx here as fd is in use.
            }
        } else {
            if (ret == MBEDTLS_ERR_NET_ACCEPT_FAILED && G_listen_fd_ctx.fd == -1) {
                 mbedtls_printf("Listener socket was closed, accept loop terminating.\n");
                 break; // Normal shutdown path
            } else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                // Don't spam for non-fatal accept errors unless debugging
                #if DEBUG_LEVEL > 0
                mbedtls_printf( "  ! mbedtls_net_accept_ocall returned -0x%04x\n", (unsigned int)-ret);
                #endif
            }
        }
    } // end while G_stop_server

exit_threadpool_shutdown:
    mbedtls_printf("\nMain accept loop finished. Shutting down thread pool...\n");
    if (G_listen_fd_ctx.fd != -1) { // Ensure listener is closed if not already by signal handler
        mbedtls_net_free_ocall(&G_listen_fd_ctx);
        G_listen_fd_ctx.fd = -1;
    }
    thread_pool_shutdown(&G_thread_pool); // This joins all worker threads

exit_main_cleanup:
    mbedtls_printf("Cleaning up Mbed TLS resources...\n");
    mbedtls_x509_crt_free(&G_srvcert);
    mbedtls_pk_free(&G_pkey);
    mbedtls_ssl_config_free(&G_ssl_config);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&G_ssl_cache);
#endif
    mbedtls_ctr_drbg_free(&G_ctr_drbg);
    mbedtls_entropy_free(&G_entropy);
    mbedtls_net_free_ocall(&G_listen_fd_ctx); // Just in case it wasn't freed

    mbedtls_printf("Server shutdown complete.\n");
    return (ret == 0 ? MBEDTLS_EXIT_SUCCESS : MBEDTLS_EXIT_FAILURE);
}

#endif /* MBEDTLS_ENTROPY_C etc. */