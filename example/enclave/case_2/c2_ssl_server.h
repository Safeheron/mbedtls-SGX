//
// Created by 何剑虹 on 2025/5/8.
//

#ifndef CASE_2_SSL_SERVER_H
#define CASE_2_SSL_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

int c2_ssl_server_main(void);

void c2_stop_server(void);
int c2_get_stop_flag(void);

#ifdef __cplusplus
}
#endif

#endif //CASE_2_SSL_SERVER_H
