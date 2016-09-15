#include <stdlib.h>
#include <getopt.h>
#include "app.h"
#include "log.h"
#include "conf.h"
#include "str2hex.h"

#if defined _WIN32 || defined __CYGWIN__
#ifndef WIN32
#define WIN32
#endif // WIN32
#endif // __MINGW32__

#define OPT_ACK                         (1)
#define OPT_AAREQ                       (2)
#define OPT_ADR                         (3)
#define OPT_APPEUI                      (4)
#define OPT_DEVEUI                      (5)
#define OPT_ANONCE                      (6)
#define OPT_DNONCE                      (7)
#define OPT_NETID                       (8)
#define OPT_CFLIST                      (9)
#define OPT_RX1DROFT                    (10)
#define OPT_RX2DR                       (11)
#define OPT_RXDELAY                     (12)
#define OPT_COUNTER                     (13)
#define OPT_PORT                        (14)
#define OPT_MOTES                       (15)
#define OPT_CLASSB                      (16)
#define OPT_FPENDING                    (17)
//#define OPT_PARSE                       (18)
//#define OPT_PACK                        (19)

struct option app_long_options[] = {
    {"help",        no_argument,            0,      'h'},
    {"version",     no_argument,            0,      'v'},

    {"burst-parse", required_argument,      0,      'c'},
    {"maccmd",      required_argument,      0,      'm'},
    {"parse",       required_argument,      0,      'p'},
    {"pack",        required_argument,      0,      'g'},
    {"pktfwd",      required_argument,      0,      'f'},

    {"band",        required_argument,      0,      'B'},
    {"nwkskey",     required_argument,      0,      'N'},
    {"appskey",     required_argument,      0,      'A'},
    {"appkey",      required_argument,      0,      'K'},

    {"type",        required_argument,      0,      'T'},
    {"devaddr",     required_argument,      0,      'D'},
    {"ack",         no_argument,            0,      OPT_ACK},
    {"aareq",       no_argument,            0,      OPT_AAREQ},
    {"adr",         no_argument,            0,      OPT_ADR},
    {"classb",      no_argument,            0,      OPT_CLASSB},
    {"fpending",    no_argument,            0,      OPT_FPENDING},
    {"fopts",       required_argument,      0,      'O'},
    {"counter",     required_argument,      0,      OPT_COUNTER},
    {"port",        required_argument,      0,      OPT_PORT},

    {"appeui",      required_argument,      0,      OPT_APPEUI},
    {"deveui",      required_argument,      0,      OPT_DEVEUI},
    {"anonce",      required_argument,      0,      OPT_ANONCE},
    {"dnonce",      required_argument,      0,      OPT_DNONCE},
    {"netid",       required_argument,      0,      OPT_NETID},
    {"cflist",      required_argument,      0,      OPT_CFLIST},
    {"rx1droft",    required_argument,      0,      OPT_RX1DROFT},
    {"rx2dr",       required_argument,      0,      OPT_RX2DR},
    {"rxdelay",     required_argument,      0,      OPT_RXDELAY},

    {"motes",       required_argument,      0,      OPT_MOTES},
    {"nodes",       required_argument,      0,      OPT_MOTES},
    {"board",       required_argument,      0,      'b'},
    {0,             0,                      0,      0},
};

const char *app_mac_type_tab[] = {
    "JR",
    "JA",
    "UU",
    "UD",
    "CU",
    "CD",
    "",
    "P",
};

const uint8_t app_dft_key[] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

const char * app_err_str_tab[] = {
    "OK",
    "MODE DUPLICATED",
    "FILE NOT FOUND",
    "MODE IMPLICIT",
    "PARAMETER INVALID",
};

const char *app_err(int err)
{
    if(err >= 0){
        return app_err_str_tab[0];
    }
    err = 0 - err;
    if(err > sizeof(app_err_str_tab)/sizeof(char *)){
        return "Unknown";
    }
    return app_err_str_tab[err];
}

void app_setopt_dft(app_opt_t *opt)
{
    opt->mode = APP_MODE_IDLE;
    memset(opt, 0, sizeof(app_opt_t));
    memcpy(opt->nwkskey, app_dft_key, APP_KEY_LEN);
    memcpy(opt->appskey, app_dft_key, APP_KEY_LEN);
    memcpy(opt->appkey, app_dft_key, APP_KEY_LEN);
    opt->hdr.bits.mtype = LW_MTYPE_MSG_UP;
}

int app_getopt(app_opt_t *opt, int argc, char **argv)
{
    int ret, index, hlen, i;
    uint8_t buf[50], addr[4] = {0};
    char *ptr;
    uint32_t tmp;

    app_setopt_dft(opt);

    opterr = 0;
    while(1){
        ret = getopt_long(argc, argv, ":hvc:m:p:g:B:N:A:K:T:D:O:C:P:f:b:", app_long_options, &index);
        if(ret == -1){
            break;
        }
        //printf("OPT %d\n", ret);
        switch(ret){
        case 'v':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_VER;
            break;
        case 'h':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_HELP;
            break;
        case 'p':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_PARSE;
            if(optarg != NULL){
                if(optarg[0] == '-'){
                    optind--;
                }else{
                    hlen = str2hex(optarg, opt->frame.buf, 256);
                    if( ( hlen > 256 ) || ( hlen <= 0 ) ){
                        return APP_ERR_PARA;
                    }
                    opt->frame.len = hlen;
                }
            }
            break;
        case 'g':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_GENERATE;
            if(optarg != NULL){
                if(optarg[0] == '-'){
                    optind--;
                }else{
                    hlen = str2hex(optarg, opt->frame.buf, 242);
                    if( ( hlen > 242 ) || ( hlen <= 0 ) ){
                        return APP_ERR_PARA;
                    }
                    opt->frame.len = hlen;
                }
            }
            break;
        case 'm':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            hlen = str2hex(optarg, opt->maccmd.buf, 256);
            if( (hlen<0) || (hlen > 256) ){
                return APP_ERR_PARA;
            }
            opt->maccmd.len = hlen;
            opt->mode = APP_MODE_MACCMD;
            break;
        case 'c':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_BURST_PARSE;
            opt->cfile = optarg;
            log_puts(LOG_NORMAL, "File name: %s", opt->cfile);
            if( access( opt->cfile, F_OK ) != -1 ){
                // file exists
                log_puts(LOG_NORMAL, "Found configuration file");
            }else{
                // file doesn't exist
                log_puts(LOG_FATAL, "Can't open %s", opt->cfile);
                return APP_ERR_CFILE;
            }
            break;
        case 'f':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_PKT_FWD;
            if(optarg != NULL){
                if(optarg[0] == '-'){
                    optind--;
                }else{
                    opt->ffile = optarg;
                    log_puts(LOG_NORMAL, "File name: %s", opt->ffile);
                    if( access( opt->ffile, F_OK ) != -1 ){
                        // file exists
                        log_puts(LOG_NORMAL, "Found packet forwarder configuration file");
                    }else{
                        // file doesn't exist
                        log_puts(LOG_FATAL, "Can't open %s", opt->ffile);
                        return APP_ERR_CFILE;
                    }
                }
            }
            break;
        case 'b':
            if(optarg != NULL){
                if(optarg[0] == '-'){
                    optind--;
                }else{
                    opt->bfile = optarg;
                    log_puts(LOG_NORMAL, "File name: %s", opt->bfile);
                    if( access( opt->bfile, F_OK ) != -1 ){
                        // file exists
                        log_puts(LOG_NORMAL, "Found packet forwarder configuration file");
                    }else{
                        // file doesn't exist
                        log_puts(LOG_FATAL, "Can't open %s", opt->bfile);
                        return APP_ERR_CFILE;
                    }
                }
            }
            break;

        case 'B':
            opt->band = EU868;
            for(i=0; i<LW_BAND_STR_TAB_NUM; i++){
                if(0 == strcmp(optarg, lw_band_str_tab[i])){
                    opt->band = (lw_band_t)i;
                    break;
                }
            }
            break;
        case OPT_DEVEUI:
            hlen = str2hex(optarg, opt->deveui, APP_EUI_LEN);
            if( hlen != APP_EUI_LEN ){
                return APP_ERR_PARA;
            }
            break;
        case OPT_APPEUI:
            hlen = str2hex(optarg, opt->appeui, APP_EUI_LEN);
            if( hlen != APP_EUI_LEN ){
                return APP_ERR_PARA;
            }
            break;
        case 'N':
            hlen = str2hex(optarg, opt->nwkskey, APP_KEY_LEN);
            if( hlen != APP_KEY_LEN ){
                return APP_ERR_PARA;
            }
            break;
        case 'A':
            hlen = str2hex(optarg, opt->appskey, APP_KEY_LEN);
            if( hlen != APP_KEY_LEN ){
                return APP_ERR_PARA;
            }
            break;
        case 'K':
            hlen = str2hex(optarg, opt->appkey, APP_KEY_LEN);
            if( hlen != APP_KEY_LEN ){
                return APP_ERR_PARA;
            }
            break;

        case 'T':
            for(i=0; i<8; i++){
                if(0 == strcasecmp(app_mac_type_tab[i], optarg) ){
                    break;
                }
            }
            if(i==8){
                return APP_ERR_PARA;
            }
            opt->hdr.bits.mtype = i;
            break;
        case 'D':
            hlen = str2hex(optarg, buf, 4);
            if( ( hlen > 4 ) || ( hlen <= 0 ) ){
                return APP_ERR_PARA;
            }
            for(i=0; i<hlen; i++){
                addr[i] = buf[hlen-1-i];
            }
            i=0;
            opt->devaddr.data = ( (uint32_t)addr[i++] << 0 );
            opt->devaddr.data |= ( (uint32_t)addr[i++] << 8 );
            opt->devaddr.data |= ( (uint32_t)addr[i++] << 16 );
            opt->devaddr.data |= ( (uint32_t)addr[i++] << 24 );
            break;
        case OPT_ACK:
            opt->ack = true;
            break;
        case OPT_AAREQ:
            opt->adrackreq = true;
            break;
        case OPT_ADR:
            opt->adr = true;
            break;
        case OPT_FPENDING:
            opt->fpending = true;
            break;
        case OPT_CLASSB:
            opt->classb = true;
            break;
        case 'C':
            hlen = str2hex(optarg, buf, 4);
            if( ( hlen > 4 ) || ( hlen <= 0 ) ){
                return APP_ERR_PARA;
            }
            opt->counter = 0;
            for(i=0; i<hlen; i++){
                opt->counter <<=8;
                opt->counter |= buf[i];
            }
            break;
        case OPT_COUNTER:
            tmp = strtoul(optarg, &ptr, 10);
            if( (*ptr != '\0') || (tmp < 0) ){
                return APP_ERR_PARA;
            }
            opt->counter = tmp;
            break;
        case 'O':
            hlen = str2hex(optarg, opt->fopts, 15);
            if( ( hlen >= APP_KEY_LEN ) || ( hlen < 0 ) ){
                return APP_ERR_PARA;
            }
            opt->foptslen = hlen;
            break;
        case 'P':
            hlen = str2hex(optarg, buf, 1);
            if( ( hlen > 1 ) || ( hlen <= 0 ) ){
                return APP_ERR_PARA;
            }
            opt->port = buf[0];
            break;
        case OPT_PORT:
            tmp = strtoul(optarg, &ptr, 10);
            if( ( *ptr != '\0' ) || ( tmp > 255 ) ){
                return APP_ERR_PARA;
            }
            opt->port = tmp;
            break;

        case OPT_ANONCE:
            hlen = str2hex(optarg, buf, 3);
            if( hlen != 3 ){
                return APP_ERR_PARA;
            }
            opt->anonce.data = 0;
            for(i=0; i<hlen; i++){
                opt->anonce.data <<=8;
                opt->anonce.data |= buf[i];
            }
            break;
        case OPT_DNONCE:
            hlen = str2hex(optarg, buf, 2);
            if( hlen != 2 ){
                return APP_ERR_PARA;
            }
            opt->dnonce.data = 0;
            for(i=0; i<hlen; i++){
                opt->dnonce.data <<=8;
                opt->dnonce.data |= buf[i];
            }
            break;
        case OPT_NETID:
            hlen = str2hex(optarg, buf, 3);
            if( hlen != 3 ){
                return APP_ERR_PARA;
            }
            opt->netid.data = 0;
            for(i=0; i<hlen; i++){
                opt->netid.data <<=8;
                opt->netid.data |= buf[i];
            }
            break;
        case OPT_CFLIST:
            hlen = str2hex(optarg, opt->cflist.buf, 16);
            if( hlen != 16 ){
                return APP_ERR_PARA;
            }
            opt->cflist.len = 16;
            break;
        case OPT_RX1DROFT:
            tmp = strtoul(optarg, &ptr, 10);
            if(*ptr != '\0'){
                return APP_ERR_PARA;
            }
            if(tmp > 7){
                return APP_ERR_PARA;
            }
            opt->rx1droft = tmp;
            break;
        case OPT_RX2DR:
            tmp = strtoul(optarg, &ptr, 10);
            if(*ptr != '\0'){
                return APP_ERR_PARA;
            }
            if(tmp > 15){
                return APP_ERR_PARA;
            }
            opt->rx2dr = tmp;
            break;
        case OPT_RXDELAY:
            tmp = strtoul(optarg, &ptr, 10);
            if(*ptr != '\0'){
                return APP_ERR_PARA;
            }
            if(tmp > 15){
                return APP_ERR_PARA;
            }
            opt->rxdelay = tmp;
            break;
        case ':':
            log_puts(LOG_NORMAL, "Optional options");
            switch(optopt){
            case 'p':
                if(opt->mode != APP_MODE_IDLE){
                    return APP_ERR_MODE_DUP;
                }
                opt->mode = APP_MODE_PARSE;
                break;
            case 'g':
                if(opt->mode != APP_MODE_IDLE){
                    return APP_ERR_MODE_DUP;
                }
                opt->mode = APP_MODE_GENERATE;
                break;
            default:
                return APP_ERR_PARA;
            }
            break;
        case '?':
            log_puts(LOG_NORMAL, "Unknown options");
            break;
        default:
            log_puts(LOG_NORMAL, "ret %d", ret);
            return APP_ERR_PARA;
        }
    }

    if(opt->mode == APP_MODE_IDLE){
        return APP_ERR_MODE;
    }

    return APP_OK;
}

int app_pkt_fwd(app_opt_t *opt)
{
    config_lgw_t lgw;

    app_log_opt(opt);

    config_lgw_parse(opt->ffile, &lgw);

#ifndef WIN32
    int i, ret;

    if (lgw_board_setconf(lgw.board.conf) != LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "WARNING: Failed to configure board");
    }

    if (lgw_lbt_setconf(lgw.lbt.conf) != LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "WARNING: Failed to configure lbt");
    }

    if (lgw_txgain_setconf(&lgw.txlut.conf) != LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "WARNING: Failed to configure concentrator TX Gain LUT");
    }

    for (i=0; i<LGW_RF_CHAIN_NB; i++) {
        if (lgw_rxrf_setconf(i, lgw.radio[i].conf) != LGW_HAL_SUCCESS) {
            log_puts(LOG_NORMAL, "WARNING: invalid configuration for radio %i", i);
        }
    }

    for (i = 0; i < LGW_MULTI_NB; ++i) {
        if (lgw_rxif_setconf(i, lgw.chan[i].conf) != LGW_HAL_SUCCESS) {
             log_puts(LOG_NORMAL, "WARNING: invalid configuration for Lora multi-SF channel %i", i);
        }
    }

    if (lgw_rxif_setconf(8, lgw.chan[8].conf) != LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "WARNING: invalid configuration for Lora multi-SF channel %i", i);
    }

    if (lgw_rxif_setconf(9, lgw.chan[9].conf) != LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "WARNING: invalid configuration for Lora multi-SF channel %i", i);
    }

    ret = lgw_start();
    if (ret == LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "INFO: [main] concentrator started, packet can now be received");
    } else {
        log_puts(LOG_NORMAL, "ERROR: [main] failed to start the concentrator");
        exit(EXIT_FAILURE);
    }

    ret = lgw_stop();
    if (ret == LGW_HAL_SUCCESS) {
        log_puts(LOG_NORMAL, "INFO: concentrator stopped successfully\n");
    } else {
        log_puts(LOG_NORMAL, "WARNING: failed to stop concentrator successfully\n");
    }
#endif

    return 0;
}

const char *app_mode_str_tab[] = {
    "IDLE",
    "HELP",
    "VERSION",
    "MACCMD",
    "PACK",
    "PARSE",
    "BATCH PARSE",
    "PACKET FORWARDER"
};

const char *app_ft_str_tab[] = {
    "Join Request",
    "Join Accept",
    "Unconfirmed Uplink",
    "Unconfirmed Downlink",
    "Confirmed Uplink",
    "Confirmed Downlink",
    "RFU",
    "Proprietary",
};

void app_log_opt(app_opt_t *opt)
{
    log_line();
    log_puts(LOG_NORMAL, "MODE:          %s", app_mode_str_tab[opt->mode]);
    if(opt->cfile != NULL){
        log_puts(LOG_NORMAL, "CONF FILE:     %s", opt->cfile);
    }
    if(opt->ffile != NULL){
        log_puts(LOG_NORMAL, "PKTFWD FILE:   %s", opt->ffile);
    }
    log_puts(LOG_INFO, "BAND:          %s", lw_band_str_tab[opt->band]);
    log_puts(LOG_INFO, "DEVEUI:        %h", opt->deveui, APP_EUI_LEN);
    log_puts(LOG_INFO, "APPEUI:        %h", opt->appeui, APP_EUI_LEN);
    log_puts(LOG_INFO, "APPKEY:        %h", opt->appkey, APP_KEY_LEN);
    log_puts(LOG_INFO, "NWKSKEY:       %h", opt->nwkskey, APP_KEY_LEN);
    log_puts(LOG_INFO, "APPSKEY:       %h", opt->appskey, APP_KEY_LEN);
    log_puts(LOG_INFO, "FRAME TYPE:    %s", app_ft_str_tab[opt->hdr.bits.mtype]);
    log_puts(LOG_INFO, "DEVADDR:       %08X", opt->devaddr.data);
    log_puts(LOG_INFO, "ADR:           %s", opt->adr?"true":"false");
    log_puts(LOG_INFO, "ACK:           %s", opt->ack?"true":"false");
    log_puts(LOG_INFO, "ADRACKREQ:     %s", opt->adrackreq?"true":"false");
    log_puts(LOG_INFO, "CLASSB:        %s", opt->classb?"true":"false");
    log_puts(LOG_INFO, "FPENDING:      %s", opt->fpending?"true":"false");
    log_puts(LOG_INFO, "FOPTS:         <%u> %H", opt->foptslen, opt->fopts, opt->foptslen);
    log_puts(LOG_INFO, "COUNTER:       %u <0x%08X>", opt->counter, opt->counter);
    log_puts(LOG_INFO, "PORT:          %u <0x%02X>", opt->port, opt->port);
    if(opt->frame.len > 0){
        log_puts(LOG_INFO, "PAYLOAD:       <%u> %H", opt->frame.len, opt->frame.buf, opt->frame.len);
    }
    log_puts(LOG_INFO, "ANONCE:        %06X", opt->anonce.data);
    log_puts(LOG_INFO, "DNONCE:        %04X", opt->dnonce.data);
    log_puts(LOG_INFO, "NETID:         %06X", opt->netid.data);
    if(opt->cflist.len > 0){
        log_puts(LOG_INFO, "CFLIST:        %H", opt->cflist.buf, opt->cflist.len);
    }
    log_puts(LOG_INFO, "RX1DROFT:      %u", opt->rx1droft);
    log_puts(LOG_INFO, "RX2DR:         %u", opt->rx2dr);
    log_puts(LOG_INFO, "RX1DELAY:      %u", opt->rxdelay);
    log_line();
}
