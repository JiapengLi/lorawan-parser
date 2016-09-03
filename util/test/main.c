#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lorawan.h"
#include "log.h"

#define PL_LEN                      (sizeof(msg_pl))
#define PL                          (msg_pl)
#define APPSKEY                     ((uint8_t*)appskey)
#define NWKSKEY                     ((uint8_t*)nwkskey)

#define APPKEY                      ((uint8_t*)appkey)
#define JRPL                        (jr_pl)
#define JRPL_LEN                    (sizeof(jr_pl))
#define JAPL                        (ja_pl)
#define JAPL_LEN                    (sizeof(ja_pl))


uint8_t appskey[]={
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

uint8_t nwkskey[]={
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

/** device-specific AES key (derived from device EUI) */
uint8_t appkey[] = {
    0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t msg_pl[]={
    0x40,
    0xAD, 0x91, 0x92, 0x00,
    0x80,
    0x01, 0x00,
    0x08,
    0xC6, 0xD2, 0x05, 0x7B,
    0x0E, 0xDA, 0xF8, 0x0A
};

// Join Request
uint8_t jr_pl[]={
//    0x00,
//    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86,
//    0x02, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
//    0x20, 0x83,
//    0x7A, 0xD8, 0x7E, 0x3B

    0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86,
    0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
    0x21, 0xF8,
    0xAF, 0x0B, 0x20, 0x34,
};

// Join Accept
uint8_t ja_pl[]={
//    0x20,
//    0x58, 0x5E, 0x54,
//    0xF1, 0x49, 0x52,
//    0xED, 0xE8, 0x9C, 0x49,
//    0xE1,
//    0xD9,
//    0x86, 0x54, 0x51, 0xFE

    0x20,
    0x1F, 0x03, 0x04, 0xBB, 0xE7, 0xC1, 0x67, 0x49, 0x05, 0x9C, 0xD4, 0x8E,
    0x50, 0x1A, 0x3A, 0x83,
};

//netid = 24 00 00
//appNonce = D2 A5 A9
//devNonce = 21 F8 00
//appkey = 86 00 00 00 00 00 00 00 86 00 00 00 00 00 00 00
//appskey = 80 A3 4F C1 8A F5 61 DC 6F 7D E3 70 8F 60 8D 0B
//nwkskey = DE 07 EF E7 FF 92 F8 19 08 38 09 0D B4 EE A5 01



lw_netid_t netid = {
    .buf[0] = 0x24,
    .buf[1] = 0x00,
    .buf[2] = 0x00,
};

lw_dnonce_t dnonce = {
    .buf[0] = 0x21,
    .buf[1] = 0xF8,
};

lw_anonce_t anonce = {
    .buf[0] = 0xD2,
    .buf[1] = 0xA5,
    .buf[2] = 0xA9,
};
uint8_t rappskey[16] = {
    0x80, 0xA3, 0x4F, 0xC1, 0x8A, 0xF5, 0x61, 0xDC,
    0x6F, 0x7D, 0xE3, 0x70, 0x8F, 0x60, 0x8D, 0x0B
};
uint8_t rnwkskey[16] = {
    0xDE, 0x07, 0xEF, 0xE7, 0xFF, 0x92, 0xF8, 0x19,
    0x08, 0x38, 0x09, 0x0D, 0xB4, 0xEE, 0xA5, 0x01,
};

uint8_t out[64];

int main(int argc, char **argv)
{
    lw_mic_t mic;
    lw_mic_t plmic;
    lw_key_t lw_key;
    lw_skey_seed_t lw_skey_seed;
    int len;
    union{
        uint16_t word;
        struct{
            uint8_t a;
            uint8_t b;
        }bytes;
    }endian;
    endian.word = 0x0001;
    if(endian.bytes.a == 0x00){
        log_puts(LOG_WARN, "Big endian");
    }else{
        log_puts(LOG_WARN, "Little endian");
    }


    log_line();
    log_puts(LOG_NORMAL, "Test Normal Message MIC");
    memcpy(plmic.buf, PL+PL_LEN-4, 4);
    lw_key.aeskey = NWKSKEY;
    lw_key.in = PL;
    lw_key.len = PL_LEN-4;
    lw_key.link = LW_UPLINK;
    lw_key.devaddr[0] = 0xAD;
    lw_key.devaddr[1] = 0x91;
    lw_key.devaddr[2] = 0x92;
    lw_key.devaddr[3] = 0x00;
    lw_key.fcnt32 = 0x00000001;

    lw_msg_mic(&mic, &lw_key);

    log_puts(LOG_NORMAL, "%08X len:%d", mic.data, lw_key.len);
    if(mic.data == plmic.data){
        log_puts(LOG_NORMAL, "MIC is OK");
    }else{
        log_puts(LOG_NORMAL, "MIC is ERROR");
    }


    log_line();
    log_puts(LOG_NORMAL, "Test Normal Message Decrypt");
    /** Test Normal Message Decrypt */
    lw_key.aeskey = APPSKEY;
    lw_key.in = PL + 13 - 4;
    lw_key.len = PL_LEN - 13;
    lw_key.link = LW_UPLINK;
    lw_key.devaddr[0] = 0xAD;
    lw_key.devaddr[1] = 0x91;
    lw_key.devaddr[2] = 0x92;
    lw_key.devaddr[3] = 0x00;
    lw_key.fcnt32 = 0x00000001;

    len = lw_encrypt(out, &lw_key);
    out[len] = 0;
    if(len>0){
        log_puts(LOG_NORMAL, "Message MIC is OK");
        log_puts(LOG_NORMAL, "%H", out, len);
        log_puts(LOG_NORMAL, "%s", out);
    }

    log_line();
    log_puts(LOG_NORMAL, "Test Join Request MIC");
    memcpy(plmic.buf, JRPL+JRPL_LEN-4, 4);
    lw_key.aeskey = APPKEY;
    lw_key.in = JRPL;
    lw_key.len = JRPL_LEN-4;
    lw_join_mic(&mic, &lw_key);
    log_puts(LOG_NORMAL, "%08X len:%d", mic.data, lw_key.len);
    if(mic.data == plmic.data){
        log_puts(LOG_NORMAL, "Join Request MIC is OK");
    }else{
        log_puts(LOG_NORMAL, "Join Request MIC is ERROR");
    }

    log_line();
    log_puts(LOG_NORMAL, "Test Join Accept Decrypt and MIC");
    lw_key.aeskey = APPKEY;
    lw_key.in = JAPL+1;
    lw_key.len = JAPL_LEN-1;
    out[0] = JAPL[0];
    len = lw_join_decrypt(out+1, &lw_key);

    if(len>0){
        log_puts(LOG_NORMAL, "Join accept encrypted payload:(%d)", JAPL_LEN);
        log_puts(LOG_NORMAL, "%H", JAPL, JAPL_LEN);
        log_puts(LOG_NORMAL, "Join accept decrypted payload:(%d)", JAPL_LEN);
        log_puts(LOG_NORMAL, "%H", out, JAPL_LEN);

        memcpy(plmic.buf, out+JAPL_LEN-4, 4);
        lw_key.aeskey = APPKEY;
        lw_key.in = out;
        lw_key.len = JAPL_LEN-4;
        lw_join_mic(&mic, &lw_key);
        log_puts(LOG_NORMAL, "%08X len:%d", mic.data, lw_key.len);
        if(mic.data == plmic.data){
            log_puts(LOG_NORMAL, "Join Request MIC is OK");
        }else{
            log_puts(LOG_NORMAL, "Join Request MIC is ERROR");
        }
    }

    log_line();
    log_puts(LOG_NORMAL, "Test NWKSKEY, APPSKEY generated");
    lw_skey_seed.aeskey = APPKEY;
    lw_skey_seed.anonce = anonce;
    lw_skey_seed.dnonce = dnonce;
    lw_skey_seed.netid = netid;
    lw_get_skeys(nwkskey, appskey, &lw_skey_seed);
    if(memcmp(nwkskey, rnwkskey, 16) == 0){
        log_puts(LOG_NORMAL, "NWKSKEY generated successfully");
        log_puts(LOG_NORMAL, "NWKSKEY:\t%H", nwkskey, len);
    }else{
        log_puts(LOG_NORMAL,"NWKSKEY generated failed");
        log_puts(LOG_NORMAL, "nwkskey:\t%H", nwkskey, len);
        log_puts(LOG_NORMAL, "rnwkskey:\t%H", rnwkskey, len);
    }

    if(memcmp(appskey, rappskey, 16) == 0){
        log_puts(LOG_NORMAL, "APPSKEY generated successfully");
        log_puts(LOG_NORMAL, "APPSKEY:\t%H", appskey, len);
    }else{
        log_puts(LOG_NORMAL, "APPSKEY generated failed");
        log_puts(LOG_NORMAL, "appskey:\t%H", appskey, len);
        log_puts(LOG_NORMAL, "rappskey:\t%H", rappskey, len);
    }

    log_init(LOG_LEVEL_VERBOSE);

    log_puts(LOG_NORMAL, "");

    log_puts(LOG_FATAL, "LOG_FATAL");
    log_puts(LOG_ERROR, "LOG_ERROR");
    log_puts(LOG_WARN, "LOG_WARN");
    log_puts(LOG_INFO, "LOG_INFO");
    log_puts(LOG_DEBUG, "LOG_DEBUG");
    log_puts(LOG_NORMAL, "LOG_NORMAL");

    uint8_t buf[5] = {0, 1, 2, 3, 4};
    log_puts(LOG_FATAL, "HI%d %H", 5, buf, 5);
    log_puts(LOG_ERROR, "HI%d %H", 5, buf, 5);
    log_puts(LOG_WARN, "HI%d %H", 5, buf, 5);
    log_puts(LOG_INFO, "HI%d %H", 5, buf, 5);
    log_puts(LOG_DEBUG, "HI%d %H", 5, buf, 5);
    log_puts(LOG_NORMAL, "HI%d %H", 5, buf, 5);

    /** Example to show how to use lorawan parser find frame counter most-significant bits */
    uint32_t fcnt = 0;
    do{
        lw_parse_key_t pkey;
        uint8_t askey[]={
            0x3B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };

        uint8_t nskey[]={
            0x3B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        uint8_t buf[]={
            0x40 , 0x01 , 0x00 , 0x00 , 0x00 , 0x80 , 0x52 ,
            0x92 , 0x08 , 0xBA , 0x82 , 0x5C , 0x67 , 0x5E ,
            0x36 , 0x80 , 0x59 , 0x52 , 0x62 , 0xAC , 0x9A , 0xEC
        };
        int ret;

        pkey.nwkskey = nskey;
        pkey.flag.bits.nwkskey = 1;
        pkey.appskey = askey;
        pkey.flag.bits.appskey = 1;

        ret = lw_parse(buf, 22, &pkey, fcnt++);
        if(ret < 0){
            //log_puts(LOG_ERROR, "DATA MESSAGE PARSE error(%d)", ret);
        }else{
            log_puts(LOG_INFO, "FRAME COUNTER 0x%08X", fcnt<<16);
            return 0;
        }
    }while(fcnt<1000);

    return 0;
}
