#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include "lorawan.h"
#include "parson.h"
#include "config.h"
#include "str2hex.h"
#include "print.h"

config_t config;

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
//        printf("arg%d %s\n", i, argv[i]);
//    }

    while ((i = getopt (argc, argv, "hc:")) != -1) {
		switch (i) {
        case 'h':
            printf("help \n");
            break;
        case 'c':
            pfile = optarg;
            printf("File name: %s\n", pfile);
            if( access( pfile, F_OK ) != -1 ) {
                // file exists
                printf("Found configuration file\n");
            }else{
                // file doesn't exist
                printf("Can't open %s\n", pfile);
                return -1;
            }
            break;
        default:
            printf("PARAMETER ERROR\n");
            return -1;
		}
	}

    ret = config_parse(pfile, &config);
    if(ret < 0){
        printf("Configuration parse error(%d)\n", ret);
    }

    if(lw_set_band(config.band) < 0){
        printf("Band error\n");
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

                print_spliter();
                printf("J-NWKSKEY:\t");
                puthbuf(jnwkskey, LW_KEY_LEN);
                printf("\n");

                printf("J-APPSKEY:\t");
                puthbuf(jappskey, LW_KEY_LEN);
                printf("\n");
                if(config.joinkey){
                    /** Overwrite default session keys */
                    pkey.nwkskey = jnwkskey;
                    pkey.flag.bits.nwkskey = 1;
                    pkey.appskey = jappskey;
                    pkey.flag.bits.appskey = 1;
                    printf("Force use session keys get from join request");
                }
            }else{
                printf("Can't get DEVNONCE/APPNONCE/NETID\n");
            }
        }
    }

    /** parse all data message */
    ll_head = config.message;
    while(ll_head != NULL){
        ret = lw_parse(ll_head->buf, ll_head->len, &pkey);
        if(ret < 0){
            printf("DATA MESSAGE PARSE error(%d)\n", ret);
        }
        ll_head = ll_head->next;
    }

    /** parse command list */
    ll_head = config.maccmd;
    while(ll_head != NULL){
        print_spliter();
        /** buf[0] -> MHDR, buf[1] ~ buf[n] -> maccmd */
        ret = lw_maccmd(ll_head->buf[0], ll_head->buf+1, ll_head->len-1);
        if(ret < 0){
            printf("MACCMD error(%d)\n", ret);
        }
        ll_head = ll_head->next;
    }

    config_free(&config);

    return 0;
}
