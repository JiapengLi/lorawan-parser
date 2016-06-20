#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <libgen.h>     // dirname, basename

#include "lorawan.h"
#include "parson.h"
#include "conf.h"
#include "str2hex.h"
#include "log.h"
#include "app.h"

#define VMAJOR          (0)
#define VMINOR          (1)
#define VPATCH          (0)

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
    lw_skey_seed_t lw_skey_seed;
    lw_dnonce_t devnonce;
    lw_anonce_t appnonce;
    lw_netid_t netid;
    uint8_t jappskey[LW_KEY_LEN];
    uint8_t jnwkskey[LW_KEY_LEN];
    config_t config;
    int logflag;

    app_opt_t opt;

    memset(&config, 0, sizeof(config_t));

    if(argc == 1){
        usage(basename(argv[0]));
        return 0;
    }

    logflag = lw_log(LW_LOG_ON);

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
        break;
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
    }

    ret = config_parse(pfile, &config);
    if(ret < 0){
        log_puts(LOG_NORMAL, "Configuration parse error(%d)", ret);
        return -1;
    }

    if(lw_set_band(config.band) < 0){
        log_puts(LOG_NORMAL, "Band error");
    }

    lw_parse_key_t pkey;
    if(config.flag&CFLAG_NWKSKEY){
        pkey.nwkskey = config.nwkskey;
        pkey.flag.bits.nwkskey = 1;
    }
    if(config.flag&CFLAG_APPSKEY){
        pkey.appskey = config.appskey;
        pkey.flag.bits.appskey = 1;
    }
    if(config.flag&CFLAG_APPKEY){
        pkey.appkey = config.appkey;
        pkey.flag.bits.appkey = 1;
    }

    /** try to parse join request/accept message */
    if(config.flag&CFLAG_JOINR){
        if(0==lw_parse(config.joinr, config.joinr_size, &pkey, 0)){

        }
    }
    if(config.flag&CFLAG_JOINA){
        /** If get join request and accept is parsed,
        then try to generate new key with JION transaction,
        the new generated key will be used to parse message */
        if(0==lw_parse(config.joina, config.joina_size, &pkey, 0)){
            if( 0==lw_get_devnonce(&devnonce) && 0==lw_get_appnonce(&appnonce) && 0==lw_get_netid(&netid) ){
                lw_skey_seed.aeskey = config.appkey;
                lw_skey_seed.anonce = appnonce;
                lw_skey_seed.dnonce = devnonce;
                lw_skey_seed.netid = netid;
                lw_get_skeys(jnwkskey, jappskey, &lw_skey_seed);

                log_line();
                log_hex(LOG_NORMAL, jnwkskey, LW_KEY_LEN, "J-NWKSKEY:\t");
                log_hex(LOG_NORMAL, jappskey, LW_KEY_LEN, "J-APPSKEY:\t");

                if(config.joinkey){
                    /** Overwrite default session keys */
                    pkey.nwkskey = jnwkskey;
                    pkey.flag.bits.nwkskey = 1;
                    pkey.appskey = jappskey;
                    pkey.flag.bits.appskey = 1;
                    log_puts(LOG_WARN, "Force use session keys get from join request");
                }
            }else{
                log_puts(LOG_WARN, "Can't get DEVNONCE/APPNONCE/NETID");
            }
        }
    }

    /** parse all data message */
    ll_head = config.message;
    while(ll_head != NULL){
        ret = lw_parse(ll_head->buf, ll_head->len, &pkey, 0);
        if(ret < 0){
            log_puts(LOG_ERROR, "DATA MESSAGE PARSE error(%d)", ret);
        }
        ll_head = ll_head->next;
    }

    /** parse command list */
    ll_head = config.maccmd;
    while(ll_head != NULL){
        if(logflag){
            log_line();
        }
        /** buf[0] -> MHDR, buf[1] ~ buf[n] -> maccmd */
        ret = lw_maccmd(ll_head->buf[0], ll_head->buf+1, ll_head->len-1);
        if(ret < 0){
            log_puts(LOG_ERROR, "MACCMD error(%d)", ret);
        }
        ll_head = ll_head->next;
    }

    config_free(&config);

    return 0;
}
