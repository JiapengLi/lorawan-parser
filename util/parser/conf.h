#ifndef __LWP_CONFIG_H
#define __LWP_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

typedef enum{
    CFLAG_NWKSKEY = (1<<0),
    CFLAG_APPSKEY = (1<<1),
    CFLAG_APPKEY  = (1<<2),
    CFLAG_JOINR   = (1<<3),
    CFLAG_JOINA   = (1<<4),
}config_flag_t;

typedef struct message{
    uint8_t *buf;
    int16_t len;
    struct message *next;
}message_t;

typedef struct motes_abp{
    uint8_t band;
    uint8_t devaddr[4];
    uint8_t nwkskey[16];
    uint8_t appskey[16];
    struct motes_abp *next;
}motes_abp_t;

typedef struct motes_otaa{
    uint8_t band;
    uint8_t deveui[8];
    uint8_t appkey[16];
    struct motes_otaa *next;
}motes_otaa_t;

typedef struct{
    uint32_t flag;
    uint8_t nwkskey[16];
    uint8_t appskey[16];
    uint8_t appkey[16];
    uint8_t band;
    bool joinkey;
    uint8_t *joinr;
    uint8_t joinr_size;
    uint8_t *joina;
    uint8_t joina_size;
    message_t *message;
    message_t *maccmd;
}config_t;

int config_parse(const char *file, config_t *config);
void config_free(config_t *config);

#endif // __CONFIG_H
