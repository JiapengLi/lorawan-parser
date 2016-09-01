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

#define LW_BAND_MAX_NUM                         (5)

typedef union{
    uint8_t data;
    struct{
    #ifdef ENABLE_BIG_ENDIAN
        uint8_t mtype           : 3;
        uint8_t rfu             : 3;
        uint8_t major           : 2;
    #else
        uint8_t major           : 2;
        uint8_t rfu             : 3;
        uint8_t mtype           : 3;

    #endif
    }bits;
}PACKED lw_mhdr_t;

typedef union{
    uint8_t data;
    struct{
    #ifdef ENABLE_BIG_ENDIAN
        uint8_t adr             : 1;
        uint8_t adrackreq       : 1;
        uint8_t ack             : 1;
        uint8_t fpending        : 1;
        uint8_t foptslen        : 4;
    #else
        uint8_t foptslen        : 4;
        uint8_t fpending        : 1;
        uint8_t ack             : 1;
        uint8_t adrackreq       : 1;
        uint8_t adr             : 1;
    #endif
    }bits;
}PACKED lw_dl_fctrl_t;

typedef union{
    uint8_t data;
    struct{
    #ifdef ENABLE_BIG_ENDIAN
        uint8_t adr             : 1;
        uint8_t adrackreq       : 1;
        uint8_t ack             : 1;
        uint8_t classb          : 1;
        uint8_t foptslen        : 4;
    #else
        uint8_t foptslen        : 4;
        uint8_t classb          : 1;
        uint8_t ack             : 1;
        uint8_t adrackreq       : 1;
        uint8_t adr             : 1;
    #endif
    }bits;
}PACKED lw_ul_fctrl_t;

//typedef union{
//    uint32_t data;
//    uint8_t buf[4];
//    struct{
//        uint32_t nwkid          : 7;
//        uint32_t nwkaddr        : 25;
//    }bits;
//}PACKED lw_devaddr_t;

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
    uint8_t devaddr[4];
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

typedef enum{
    LW_BAND_EU868,
    LW_BAND_US915,
    LW_BAND_CN780,
    LW_BAND_EU433,
    LW_BAND_CUSTOM,
}lw_band_t;

#define LW_DR(sf, bw)               ( (uint8_t)( (sf) | ((bw)<<4) ))
#define LW_DR_RFU                   (0xFF)
#define LW_POW_RFU                  (-128)

/* Channel Mask Control */
#define LW_CMC(from, to)            ( (uint8_t)( (from) | ((to)<<8) ))
#define LW_CMC_RFU                  (0xFFFF)
#define LW_CMC_ALL_ON               (0xFFFE)
#define LW_CMC_ALL_125KHZ_ON        (0xFFFD)
#define LW_CMC_ALL_125KHZ_OFF       (0xFFFC)

#define LW_LOG_OFF                  (0)
#define LW_LOG_ON                   (1)

enum{
    FSK = 0,
    SF5 = 5,
    SF6 = 6,
    SF7 = 7,
    SF8 = 8,
    SF9 = 9,
    SF10 = 10,
    SF11 = 11,
    SF12 = 12,
};

enum{
    BW125 = 0,      // 125*1 125*pow(2,n)
    BW250 = 1,      // 125*2
    BW500 = 2,      // 125*4
};

typedef union{
    uint8_t data;
    struct{
    #ifdef ENABLE_BIG_ENDIAN
        uint8_t rfu             : 2;
        uint8_t bw              : 2;
        uint8_t sf              : 4;
    #else
        uint8_t sf              : 4;
        uint8_t bw              : 2;
        uint8_t rfu             : 2;
    #endif
    }bits;
}lw_dr_t;

int lw_log(int logflag);
int lw_maccmd(uint8_t mac_header, uint8_t *opts, int len);
int lw_parse(uint8_t *buf, int len, lw_parse_key_t *pkey, uint32_t fcnt16_msb);
int lw_get_dmsg(uint8_t *buf, int max_len);
int lw_get_devnonce(lw_dnonce_t *dnonce);
int lw_get_appnonce(lw_anonce_t *anonce);
int lw_get_netid(lw_netid_t *netid);

int lw_set_band(lw_band_t band);

/** crypto functions */
void lw_msg_mic(lw_mic_t* mic, lw_key_t *key);
void lw_join_mic(lw_mic_t* mic, lw_key_t *key);
int lw_encrypt(uint8_t *out, lw_key_t *key);
int lw_join_decrypt(uint8_t *out, lw_key_t *key);
int lw_join_encrypt(uint8_t *out, lw_key_t *key);
void lw_get_skeys(uint8_t *nwkskey, uint8_t *appskey, lw_skey_seed_t *seed);

#endif // __LORAWAN_H

