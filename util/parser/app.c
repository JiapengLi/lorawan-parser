#include "app.h"
#include "log.h"
#include <getopt.h>

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

struct option app_long_options[] = {
    {"devaddr",     required_argument,      0,      'D'},
    {"ack",         no_argument,            0,      OPT_ACK},
    {"aareq",       no_argument,            0,      OPT_AAREQ},
    {"adr",         no_argument,            0,      OPT_ADR},
    {"appeui",      required_argument,      0,      OPT_APPEUI},
    {"deveui",      required_argument,      0,      OPT_DEVEUI},
    {"anonce",      required_argument,      0,      OPT_ANONCE},
    {"dnonce",      required_argument,      0,      OPT_DNONCE},
    {"netid",       required_argument,      0,      OPT_NETID},
    {"cflist",      required_argument,      0,      OPT_CFLIST},
    {"rx1droft",    required_argument,      0,      OPT_RX1DROFT},
    {"rx2dr",       required_argument,      0,      OPT_RX2DR},
    {"rxdelay",     required_argument,      0,      OPT_RXDELAY},
    {0,             0,                      0,      0},
 };

int app_getopt(app_opt_t *opt, int argc, char **argv)
{
    int ret, index;

    opt->mode = APP_MODE_IDLE;

    while(1){
        ret = getopt_long(argc, argv, "hvc:m:pgB:N:A:K:T:D:O:C:P:F", app_long_options, &index);
        if(ret == -1){
            break;
        }
        switch(ret){
        case 'v':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_VER;
            return APP_OK;
        case 'h':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_HELP;
            return APP_OK;
        case 'p':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_VER;
            return APP_OK;
        case 'g':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_GENERATE;
            return APP_OK;
        case 'm':
            if(opt->mode != APP_MODE_IDLE){
                return APP_ERR_MODE_DUP;
            }
            opt->mode = APP_MODE_MACCMD;
            return APP_OK;
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
        case OPT_ACK:
            break;
        case OPT_AAREQ:
            break;
        default:
            return APP_ERR_PARA;
        }
    }

    if(opt->mode == APP_MODE_IDLE){
        return APP_ERR_MODE;
    }

    return APP_OK;
}

