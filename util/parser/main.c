#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <libgen.h>     // dirname, basename

#include "lw.h"
#include "parson.h"
#include "conf.h"
#include "str2hex.h"
#include "log.h"
#include "app.h"
#include "version.h"

/**
    JR: Join Request
    JA: Join Accept
    UU: Unconfirmed Data Up
    UD: Unconfirmed Data Down
    CU: Confirmed Data Up
    CD: Confirmed Data Down
    P:  Proprietary
*/
void usage(char *name)
{
    log_puts(LOG_NORMAL, "Usage: %s [OPTIONS]", name);
    log_puts(LOG_NORMAL, " -h                       Help");
    log_puts(LOG_NORMAL, " -v                       Version");
    log_line();
    log_puts(LOG_NORMAL, " -c           <file>      Get configuration from json format file");
    log_puts(LOG_NORMAL, " -m           <hex>       Parse MAC command");
    log_puts(LOG_NORMAL, " -p                       Parse packet");
    log_puts(LOG_NORMAL, " -g                       Generate packet");
    log_line();
    log_puts(LOG_NORMAL, " -B           <string>    Physical band EU868/US915/EU434/AU920/CN780/CN470");
    log_puts(LOG_NORMAL, " -N           <hex>       NwkSKey");
    log_puts(LOG_NORMAL, " -A           <hex>       AppSKey");
    log_puts(LOG_NORMAL, " -K           <hex>       AppKey");
    log_line();
    log_puts(LOG_NORMAL, " -T           <string>    Frame type (JR/JA/UU/UD/CU/CD/P)");
    log_puts(LOG_NORMAL, " -D           <hex>       DevAddr");
    log_puts(LOG_NORMAL, " --devaddr    <hex>       DevAddr, same as devaddr");
    log_puts(LOG_NORMAL, " --ack                    FCtrl ACK");
    log_puts(LOG_NORMAL, " --aareq                  FCtrl ADRACKReq");
    log_puts(LOG_NORMAL, " --adr                    FCtrl ADR");
    log_puts(LOG_NORMAL, " -O           <hex>       FOpts, LoRaWAN Options");
    log_puts(LOG_NORMAL, " -C           <int>       Frame counter");
    log_puts(LOG_NORMAL, " -P           <int>       Port");
    log_line();
    log_puts(LOG_NORMAL, " -F           <hex>       Payload for generating, or LoRaWAN frame for parsing");
    log_line();
    log_puts(LOG_NORMAL, " --appeui     <hex>       AppEui");
    log_puts(LOG_NORMAL, " --deveui     <hex>       DevEui");
    log_puts(LOG_NORMAL, " --anonce     <hex>       AppNonce");
    log_puts(LOG_NORMAL, " --dnonce     <hex>       DevNonce");
    log_puts(LOG_NORMAL, " --netid      <hex>       NetId");
    log_puts(LOG_NORMAL, " --cflist     <hex>       CFList");
    log_puts(LOG_NORMAL, " --rx1droft   <int>       RX1DRoffset (0~7)");
    log_puts(LOG_NORMAL, " --rx2dr      <int>       RX2DataRate (0~15)");
    log_puts(LOG_NORMAL, " --rxdelay    <int>       RxDelay (0~15)");

}

int main(int argc, char **argv)
{
    int ret;
    char *pfile = NULL;
    message_t * ll_head;
    lw_frame_t frame;
    config_t config;
    app_opt_t opt;
    lw_key_grp_t kgrp;

    memset(&config, 0, sizeof(config_t));

    if(argc == 1){
        usage(basename(argv[0]));
        return 0;
    }

    ret = app_getopt(&opt, argc, argv);
    if(ret < 0){
        log_puts(LOG_FATAL, "PARAMETER ERROR");
        usage(basename(argv[0]));
        return -1;
    }

    switch(opt.mode){
    case APP_MODE_HELP:
        usage(basename(argv[0]));
        return 0;
    case APP_MODE_VER:
        log_puts(LOG_NORMAL, "%d.%d.%d", VMAJOR, VMINOR, VPATCH);
        return 0;
    case APP_MODE_MACCMD:
        ret = lw_log_maccmd(opt.hdr, opt.maccmd.buf, opt.maccmd.len);
        if(ret < 0){
            log_puts(LOG_ERROR, "MACCMD error(%d)", ret);
            return -1;
        }
        return 0;
    case APP_MODE_PARSE:
        break;
    case APP_MODE_BURST_PARSE:
        pfile = opt.cfile;
        break;
    case APP_MODE_GENERATE:
        break;
    default:
        log_puts(LOG_FATAL, "UNKNOWN MODE");
        usage(basename(argv[0]));
        return -1;
    }

    if(opt.mode != APP_MODE_BURST_PARSE){
        log_puts(LOG_WARN, "Mode is not supported");
        return -1;
    }

    ret = config_parse(pfile, &config);
    if(ret < 0){
        log_puts(LOG_NORMAL, "Configuration parse error(%d)", ret);
        return -1;
    }

    lw_init(config.band);
//    if(lw_set_band(config.band) < 0){
//        log_puts(LOG_NORMAL, "Band error");
//    }


    memset(&kgrp, 0, sizeof(lw_key_grp_t));
    if(config.flag&CFLAG_NWKSKEY){
        kgrp.nwkskey = config.nwkskey;
        kgrp.flag.bits.nwkskey = 1;
    }
    if(config.flag&CFLAG_APPSKEY){
        kgrp.appskey = config.appskey;
        kgrp.flag.bits.appskey = 1;
    }
    if(config.flag&CFLAG_APPKEY){
        kgrp.appkey = config.appkey;
        kgrp.flag.bits.appkey = 1;
    }
    lw_set_key(&kgrp);

    /** try to parse join request/accept message */
    if(config.flag&CFLAG_JOINR){
        log_line();
        if(LW_OK == lw_parse(&frame, config.joinr, config.joinr_size)){
            lw_log(&frame, config.joinr, config.joinr_size);
        }
    }

    if(config.flag&CFLAG_JOINA){
        log_line();
        /** If get join request and accept is parsed,
        then try to generate new key with JION transaction,
        the new generated key will be used to parse message */
        if(LW_OK == lw_parse(&frame, config.joina, config.joina_size)){
            lw_log(&frame, config.joina, config.joina_size);
        }else{
            log_puts(LOG_WARN, "JOIN REQUEST PARSE ERROR");
        }
    }

    /** parse all data message */
    ll_head = config.message;
    while(ll_head != NULL){
        log_line();
        ret = lw_parse(&frame, ll_head->buf, ll_head->len);
        if(ret == LW_OK){
            lw_log(&frame, ll_head->buf, ll_head->len);
        }else{
            log_puts(LOG_ERROR, "DATA MESSAGE PARSE error(%d)", ret);
        }
        ll_head = ll_head->next;
    }

    /** parse command list */
    ll_head = config.maccmd;
    while(ll_head != NULL){
        log_line();
        /** buf[0] -> MHDR, buf[1] ~ buf[n] -> maccmd */
        ret = lw_log_maccmd(ll_head->buf[0], ll_head->buf+1, ll_head->len-1);
        if(ret < 0){
            log_puts(LOG_ERROR, "MACCMD error(%d)", ret);
        }
        ll_head = ll_head->next;
    }

    lw_log_all_node();

    config_free(&config);

    return 0;
}
