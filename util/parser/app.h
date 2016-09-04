#ifndef __APP_H
#define __APP_H

#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include "lw.h"

#define APP_KEY_LEN                 (16)
#define APP_EUI_LEN                 (8)

typedef enum {
    APP_MODE_IDLE,
    APP_MODE_HELP,
    APP_MODE_VER,
    APP_MODE_MACCMD,
    APP_MODE_GENERATE,
    APP_MODE_PARSE,
    APP_MODE_BURST_PARSE,
}app_mode_t;

typedef enum{
    APP_OK = 0,
    APP_ERR_MODE_DUP = -1,
    APP_ERR_CFILE = -2,
    APP_ERR_MODE = -3,
    APP_ERR_PARA = -4,              // Parameter format is in valid
}app_ret_t;

typedef struct{
    app_mode_t mode;

    char *cfile;

    lw_band_t band;
    uint8_t appeui[APP_EUI_LEN];
    uint8_t deveui[APP_EUI_LEN];
    uint8_t nwkskey[APP_KEY_LEN];
    uint8_t appskey[APP_KEY_LEN];
    uint8_t appkey[APP_KEY_LEN];

    lw_mhdr_t hdr;
    lw_devaddr_t devaddr;
    bool ack;
    bool adrackreq;
    bool adr;
    bool classb;
    bool fpending;
    uint8_t foptslen;
    uint8_t fopts[16];
    uint32_t counter;
    struct{
        int len;
        uint8_t buf[256];
    }maccmd;
    uint8_t port;
    struct{
        uint16_t len;
        uint8_t buf[256];
    }frame;

    lw_anonce_t anonce;
    lw_dnonce_t dnonce;
    lw_netid_t netid;
    struct{
        uint8_t len;
        uint8_t buf[16];
    }cflist;
    uint8_t rx1droft;
    uint8_t rx2dr;
    uint8_t rxdelay;
}app_opt_t;

const char *app_err(int err);
int app_getopt(app_opt_t *opt, int argc, char **argv);
void app_log_opt(app_opt_t *opt);

#endif // __APP_H
