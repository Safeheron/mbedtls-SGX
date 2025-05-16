//
// Created by 何剑虹 on 2025/5/8.
//

#ifndef HTTPS_SERVER_H
#define HTTPS_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

int ssl_server_2_main(void);

void ssl_server_2_stop_server(void);
int ssl_server_2_get_stop_flag(void);

#ifdef __cplusplus
}
#endif

#endif //HTTPS_SERVER_H
