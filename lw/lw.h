#ifndef __LW_H
#define __LW_H
#include <stdint.h>
#include <stdbool.h>
#include "lw-macro.h"
#include "loragw_hal.h"

#if defined(__CC_ARM) || defined(__GNUC__)
#define PACKED                                      __attribute__( ( __packed__ ) )
#elif defined( __ICCARM__ )
#define PACKED                                      __packed
#else
    #warning Not supported compiler type
#endif

#define LW_MAX_NODES                        (100)
#define LW_KEY_LEN                          (16)
#define LW_MIC_LEN                          (4)

#define LW_DR(sf, bw)               ( (uint8_t)( (sf) | ((bw)<<4) ))
#define LW_DR_RFU                   (0xFF)
#define LW_POW_RFU                  (-128)

/* Channel Mask Control */
#define LW_CMC(from, to)            ( (uint8_t)( (from) | ((to)<<8) ))
#define LW_CMC_RFU                  (0xFFFF)
#define LW_CMC_ALL_ON               (0xFFFE)
#define LW_CMC_ALL_125KHZ_ON        (0xFFFD)
#define LW_CMC_ALL_125KHZ_OFF       (0xFFFC)

enum{
    DR0 = 0,
    DR1 = 1,
    DR2 = 2,
    DR3 = 3,
    DR4 = 4,
    DR5 = 5,
    DR6 = 6,
    DR7 = 7,
    DR8 = 8,
    DR9 = 9,
    DR10 = 11,
    DR12 = 12,
    DR13 = 13,
    DR14 = 14,
    DR15 = 15,
};

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

#define LW_LGW_DR(sf,bw)            ( (uint16_t)( (sf) | ((bw)<<8) ))

typedef enum{
    ABP,
    OTAA,
}lw_mode_t;

typedef enum{
    CLASS_A_RX1,
    CLASS_A_RX2,
    CLASS_B_RX,
    CLASS_C_RX,
}lw_rxwin_t;

typedef enum{
    EU868,
    US915,
    CN779,
    EU433,
    AU915,
    CN470,
    AS923,
    KR920,
    IN865,
    RU864,
}lw_band_t;

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
    uint32_t data;
    uint8_t buf[4];
    struct{
    #ifdef ENABLE_BIG_ENDIAN
        uint32_t nwkaddr        : 25;
        uint32_t nwkid          : 7;
    #else
        uint32_t nwkid          : 7;
        uint32_t nwkaddr        : 25;
    #endif
    }bits;
}PACKED lw_devaddr_t;

typedef union{
    uint32_t data;
    uint8_t buf[4];
}PACKED lw_mic_t;

typedef union{
    uint32_t data;
}PACKED lw_anonce_t;

typedef lw_anonce_t lw_netid_t;

typedef union{
    uint16_t data;
}PACKED lw_dnonce_t;

typedef union{
    uint8_t data;
    struct{
    #ifdef ENABLE_BIG_ENDIAN
        uint8_t rfu             : 4;
        uint8_t del             : 4;
    #else
        uint8_t del             : 4;
        uint8_t rfu             : 4;
    #endif
    }bits;
}PACKED lw_rxdelay_t;

typedef union{
    uint8_t data;
    struct{
    #ifdef ENABLE_BIG_ENDIAN
        uint8_t rfu             : 1;
        uint8_t rx1droft        : 3;
        uint8_t rx2dr           : 4;
    #else
        uint8_t rx2dr           : 4;
        uint8_t rx1droft        : 3;
        uint8_t rfu             : 1;
    #endif
    }bits;
}PACKED lw_dlset_t;

typedef struct{
    lw_devaddr_t devaddr;
    union{
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
        }PACKED ul;
        struct{
    #ifdef ENABLE_BIG_ENDIAN
            uint8_t adr             : 1;
            uint8_t rfu             : 1;
            uint8_t ack             : 1;
            uint8_t fpending        : 1;
            uint8_t foptslen        : 4;
    #else
            uint8_t foptslen        : 4;
            uint8_t fpending        : 1;
            uint8_t ack             : 1;
            uint8_t rfu             : 1;
            uint8_t adr             : 1;
    #endif
        }PACKED dl;
    }PACKED fctrl;
    uint32_t fcnt;
    uint8_t fopts[15];
    uint8_t fport;
    uint8_t fpl[255];
    uint8_t flen;
}lw_pl_mac_t;

typedef struct{
    //uint8_t appeui[8];
    //uint8_t deveui[8];
    lw_dnonce_t devnonce;
}lw_pl_jr_t;

typedef struct{
    lw_anonce_t appnonce;
    lw_netid_t netid;
    lw_devaddr_t devaddr;
    lw_dlset_t dlsettings;
    lw_rxdelay_t rxdelay;
    uint8_t cflist[16];
    int cflist_len;
    uint8_t nwkskey[16];
    uint8_t appskey[16];
}lw_pl_ja_t;

//lw.node.abp.devaddr;
typedef struct lw{
    uint8_t flag;
    lw_mode_t mode;
    uint8_t joined;
    uint8_t appeui[8];
    uint8_t deveui[8];
    lw_devaddr_t devaddr;
    uint8_t nwkskey[16];
    uint8_t appskey[16];

    uint8_t appkey[16];
    lw_dnonce_t devnonce;
    lw_anonce_t appnonce;
    lw_netid_t netid;

    uint32_t ufsum;
    uint32_t uflost;
    uint32_t ufcnt;
    uint32_t dfcnt;

    uint8_t dlport;
    uint16_t dlsize;
    uint8_t *dlbuf;

    uint8_t maccmdsize;
    uint8_t maccmd[15];

    lw_rxwin_t rxwin;
    lw_dlset_t dlsettings;
    lw_rxdelay_t rxdelay;

    struct lw *next;
}lw_node_t;

typedef struct{
    lw_node_t *node;
    uint8_t deveui[8];
    uint8_t appeui[8];
    lw_mhdr_t mhdr;
    union{
        lw_pl_mac_t mac;
        lw_pl_jr_t jr;
        lw_pl_ja_t ja;
    }pl;
    lw_mic_t mic;
    uint8_t buf[256];
    int len;
}lw_frame_t;

typedef struct{
    uint8_t *aeskey;
    lw_anonce_t anonce;
    lw_netid_t netid;
    lw_dnonce_t dnonce;
}lw_skey_seed_t;

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
    uint8_t cmd;
    union{
        uint8_t buf[14];
        struct{
            uint8_t margin;
            uint8_t gwcnt;
        }lchk_ans;

        struct{
            union{
                uint8_t data;
                struct{
                #ifdef ENABLE_BIG_ENDIAN
                    uint8_t dr              : 4;
                    uint8_t txpow           : 4;
                #else
                    uint8_t txpow           : 4;
                    uint8_t dr              : 4;
                #endif
                }bits;
            }dr_txpow;
            uint8_t chmsk[2];
            union{
                uint8_t data;
                struct{
                #ifdef ENABLE_BIG_ENDIAN
                    uint8_t rfu             : 1;
                    uint8_t chmaskcntl      : 3;
                    uint8_t nbtrans         : 4;
                #else
                    uint8_t nbtrans         : 4;
                    uint8_t chmaskcntl      : 3;
                    uint8_t rfu             : 1;
                #endif

                }bits;
            }redundancy;
        }ladr_req;

        struct{
            union{
                uint8_t data;
                struct{
                #ifdef ENABLE_BIG_ENDIAN
                    uint8_t rfu             : 4;
                    uint8_t maxdc           : 4;
                #else
                    uint8_t maxdc           : 4;
                    uint8_t rfu             : 4;
                #endif
                }bits;
            }dcpl;
        }dcap_req;

        struct{
            lw_dlset_t dlsettings;
            uint8_t freq[3];
        }dn2p_req;

//        struct{
//        }devs_req;

        struct{
            uint8_t chindex;
            uint8_t freq[3];
            union{
                uint8_t data;
                struct{
                #ifdef ENABLE_BIG_ENDIAN
                    uint8_t max             : 4;
                    uint8_t min             : 4;
                #else
                    uint8_t min             : 4;
                    uint8_t max             : 4;
                #endif

                }bits;
            }drrange;
        }snch_req;

        struct{
            union{
                uint8_t data;
                struct{
                #ifdef ENABLE_BIG_ENDIAN
                    uint8_t rfu             : 4;
                    uint8_t del             : 4;
                #else
                    uint8_t del             : 4;
                    uint8_t rfu             : 4;
                #endif
                }bits;
            }rxtspl;
        }rxts_req;
    }pl;
    uint8_t len;
}lw_maccmd_t;

typedef struct{
    struct{
        uint32_t freq;
        uint8_t dr;
    }rxwin2;
}lw_config_t;

typedef struct{
    union{
        uint8_t data;
        struct{
            uint8_t nwkskey :1;
            uint8_t appskey :1;
            uint8_t appkey  :1;
        }bits;
    }flag;
    uint8_t *nwkskey;
    uint8_t *appskey;
    uint8_t *appkey;
}lw_key_grp_t;

typedef struct lgw_pkt_rx_s lw_rxpkt_t;
typedef struct lgw_pkt_tx_s lw_txpkt_t;

typedef struct{
    lw_band_t band;
    const char *name;
    const uint8_t *dr_tab;
    struct{
        uint8_t max_eirp_index;
        uint8_t max_tx_power_index;
    }power;
    const uint16_t *chmaskcntl_tab;
}lw_region_t;

#include "lw-log.h"

int lw_init(lw_band_t band);
int lw_add(lw_node_t *node);
lw_node_t *lw_get_node(uint8_t *deveui);
int lw_del(uint8_t *deveui);
int lw_set_key(lw_key_grp_t *kgrp);
int lw_add_tx(uint8_t *deveui, uint8_t port, uint8_t *buf, uint16_t size);
int lw_tx_maccmd(uint8_t *deveui, lw_maccmd_t *maccmd);
int lw_parse(lw_frame_t *frame, uint8_t *buf, int len);
int lw_pack(lw_frame_t *frame, uint8_t *buf, int *len);
int lw_answer(lw_frame_t *frame, lw_rxpkt_t *rxpkt, lw_txpkt_t *txpkt);

void lw_cpy(uint8_t *dest, uint8_t *src, int len);
int lw_maccmd_valid(uint8_t mac_header, uint8_t *opts, int len);

int8_t lw_get_dr(uint8_t mod, uint32_t datarate, uint8_t bw);
int8_t lw_get_rf(uint8_t dr, uint8_t *mod, uint32_t *datarate, uint8_t *bw, uint8_t *fdev);

lw_band_t lw_get_band_type(const char *band);
const char *lw_get_band_name(lw_band_t band);

uint32_t lw_read_dw(uint8_t *buf);

/** crypto functions */
void lw_msg_mic(lw_mic_t* mic, lw_key_t *key);
void lw_join_mic(lw_mic_t* mic, lw_key_t *key);
int lw_encrypt(uint8_t *out, lw_key_t *key);
int lw_join_decrypt(uint8_t *out, lw_key_t *key);
int lw_join_encrypt(uint8_t *out, lw_key_t *key);
void lw_get_skeys(uint8_t *nwkskey, uint8_t *appskey, lw_skey_seed_t *seed);

void lw_test(void);

#endif
