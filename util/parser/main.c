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

config_t config;

void usage(char *name)
{
    log_puts(LOG_NORMAL, "Usage: %s [OPTIONS]... [JSON FILE]", name);
    log_puts(LOG_NORMAL, " -h    Help");
    log_puts(LOG_NORMAL, " -c    Get configuration from json format file");
}


int main(int argc, char **argv)
{
    int i;
    int ret;
    char *pfile = NULL;
    message_t * ll_head;
    lw_skey_seed_t lw_skey_seed;
    lw_dnonce_t devnonce;
    lw_anonce_t appnonce;
    lw_netid_t netid;
    uint8_t jappskey[LW_KEY_LEN];
    uint8_t jnwkskey[LW_KEY_LEN];

    memset(&config, 0, sizeof(config_t));

//    for(i=0; i<argc; i++){
//        log_puts(LOG_NORMAL, "arg%d %s", i, argv[i]);
//    }

    lw_log(LW_LOG_OFF);

    while ((i = getopt (argc, argv, "hc:")) != -1) {
        switch (i) {
        case 'h':
            usage(basename(argv[0]));
            return 0;
        case 'c':
            pfile = optarg;
            log_puts(LOG_NORMAL, "File name: %s", pfile);
            if( access( pfile, F_OK ) != -1 ) {
                // file exists
                log_puts(LOG_NORMAL, "Found configuration file");
            }else{
                // file doesn't exist
                log_puts(LOG_FATAL, "Can't open %s", pfile);
                return -1;
            }
            break;
        default:
            log_puts(LOG_FATAL, "PARAMETER ERROR");
            usage(basename(argv[0]));
            return -1;
        }
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
        if(0==lw_parse(config.joinr, config.joinr_size, &pkey)){

        }
    }
    if(config.flag&CFLAG_JOINA){
        /** If get join request and accept is parsed,
        then try to generate new key with JION transaction,
        the new generated key will be used to parse message */
        if(0==lw_parse(config.joina, config.joina_size, &pkey)){
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
        ret = lw_parse(ll_head->buf, ll_head->len, &pkey);
        if(ret < 0){
            log_puts(LOG_ERROR, "DATA MESSAGE PARSE error(%d)", ret);
        }
        ll_head = ll_head->next;
    }

    /** parse command list */
    ll_head = config.maccmd;
    while(ll_head != NULL){
        log_line();
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
