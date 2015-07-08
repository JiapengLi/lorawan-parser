#ifndef __LORAWAN_H
#define __LORAWAN_H

#include <stdint.h>
#include "lw-macro.h"

#if defined(__CC_ARM) || defined(__GNUC__)
#define PACKED                                      __attribute__( ( __packed__ ) )
#elif defined( __ICCARM__ )
#define PACKED                                      __packed
#else
    #warning Not supported compiler type
#endif

#define LW_KEY_LEN              (16)
#define LW_MIC_LEN              (4)


typedef union{
    uint8_t data;
    struct{
        uint8_t major           : 2;
        uint8_t rfu             : 3;
        uint8_t mtype           : 3;
    }bits;
}PACKED lw_mhdr_t;

typedef union{
    uint8_t data;
    struct{
        uint8_t foptslen        : 4;
        uint8_t fpending        : 1;
        uint8_t ack             : 1;
        uint8_t adrackreq       : 1;
        uint8_t adr             : 1;
    }bits;
}PACKED lw_dl_fctrl_t;

typedef union{
    uint8_t data;
    struct{
        uint8_t foptslen        : 4;
        uint8_t classb          : 1;
        uint8_t ack             : 1;
        uint8_t adrackreq       : 1;
        uint8_t adr             : 1;
    }bits;
}PACKED lw_ul_fctrl_t;

typedef union{
    uint32_t data;
    uint8_t buf[4];
    struct{
        uint32_t nwkid          : 7;
        uint32_t nwkaddr        : 25;
    }bits;
}PACKED lw_devaddr_t;

typedef union{
    uint32_t data;
    uint8_t buf[4];
}PACKED lw_mic_t;

typedef union{
    uint32_t data               :24;
    uint8_t buf[3];
}PACKED lw_anonce_t;

typedef lw_anonce_t lw_netid_t;

typedef union{
    uint16_t data;
    uint8_t buf[2];
}PACKED lw_dnonce_t;

typedef struct{
    lw_mhdr_t mhdr;
    uint32_t devaddr;
    union{
        lw_ul_fctrl_t ul;
        lw_dl_fctrl_t dl;
    }fctrl;
    uint16_t fcnt;
    uint8_t *fopts;
    uint8_t fport;

    lw_mic_t mic;
}lw_t;

typedef enum{
    LW_UPLINK = 0,
    LW_DOWNLINK = 1,
}lw_link_t;

typedef struct{
    uint8_t *aeskey;
    uint8_t *in;
    uint16_t len;
    lw_devaddr_t devaddr;
    lw_link_t link;
    uint32_t fcnt32;
}lw_key_t;

typedef struct{
    uint8_t *aeskey;
    lw_anonce_t anonce;
    lw_netid_t netid;
    lw_dnonce_t dnonce;
}lw_skey_seed_t;

typedef struct{
    union{
        uint8_t data;
        struct{
            uint8_t nwkskey         : 1;
            uint8_t appskey         : 1;
            uint8_t appkey          : 1;
        }bits;
    }flag;
    uint8_t *nwkskey;
    uint8_t *appskey;
    uint8_t *appkey;
}lw_parse_key_t;

typedef struct{
    uint8_t buf[256];
    int16_t len;
}lw_buffer_t;

int lw_maccmd(uint8_t mac_header, uint8_t *opts, int len);
int lw_parse(uint8_t *buf, int len, lw_parse_key_t *pkey);
int lw_get_dmsg(uint8_t *buf, int max_len);
int lw_get_devnonce(lw_dnonce_t *dnonce);
int lw_get_appnonce(lw_anonce_t *anonce);
int lw_get_netid(lw_netid_t *netid);

/** crypto functions */
void lw_msg_mic(lw_mic_t* mic, lw_key_t *key);
void lw_join_mic(lw_mic_t* mic, lw_key_t *key);
int lw_encrypt(uint8_t *out, lw_key_t *key);
int lw_join_decrypt(uint8_t *out, lw_key_t *key);
int lw_join_encrypt(uint8_t *out, lw_key_t *key);
void lw_get_skeys(uint8_t *nwkskey, uint8_t *appskey, lw_skey_seed_t *seed);

#endif // __LORAWAN_H

