#ifndef __APP_H
#define __APP_H

#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

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
    struct{
        int len;
        uint8_t buf[256];
    }maccmd;
    uint8_t hdr;
}app_opt_t;

int app_getopt(app_opt_t *opt, int argc, char **argv);

#endif // __APP_H
