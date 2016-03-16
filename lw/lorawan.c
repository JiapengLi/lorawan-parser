#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "lorawan.h"
#include "aes.h"
#include "cmac.h"
#include "log.h"

int lw_mtype_join_accept(uint8_t *buf, int len, lw_parse_key_t *pkey);
int lw_mtype_join_request(uint8_t *buf, int len, lw_parse_key_t *pkey);
int lw_mtype_msg_up(uint8_t *buf, int len, lw_parse_key_t *pkey);
int lw_mtype_msg_down(uint8_t *buf, int len, lw_parse_key_t *pkey);
int lw_mtype_cmsg_up(uint8_t *buf, int len, lw_parse_key_t *pkey);
int lw_mtype_cmsg_down(uint8_t *buf, int len, lw_parse_key_t *pkey);
int lw_mtype_rfu(uint8_t *buf, int len, lw_parse_key_t *pkey);
int lw_mtype_proprietary(uint8_t *buf, int len, lw_parse_key_t *pkey);

#define LW_FLAG_BUF_OK                  (1<<0)
#define LW_FLAG_DNONCE_OK               (1<<1)
#define LW_FLAG_ANONCE_OK               (1<<2)
#define LW_FLAG_NETID_OK                (1<<3)

lw_band_t lw_band = LW_BAND_EU868;
uint32_t lw_flag = 0;
lw_buffer_t lw_buf;
lw_dnonce_t lw_dnonce;
lw_anonce_t lw_anonce;
lw_netid_t lw_netid;
uint8_t lw_appskey[LW_KEY_LEN];
uint8_t lw_nwkskey[LW_KEY_LEN];

typedef int (*lw_mtype_func_p) (uint8_t *buf, int len, lw_parse_key_t *pkey);

const uint8_t lw_dr_tab[][16] = {
    /* EU868 */
    {
        LW_DR(SF12, BW125),    // DR0
        LW_DR(SF11, BW125),    // DR1
        LW_DR(SF10, BW125),    // DR2
        LW_DR(SF9, BW125),     // DR3
        LW_DR(SF8, BW125),     // DR4
        LW_DR(SF7, BW125),     // DR5
        LW_DR(SF7, BW250),     // DR7
        LW_DR(FSK, BW125),     // DR8
        LW_DR_RFU,             // DR9
        LW_DR_RFU,             // DR10
        LW_DR_RFU,             // DR11
        LW_DR_RFU,             // DR12
        LW_DR_RFU,             // DR13
        LW_DR_RFU,             // DR14
        LW_DR_RFU,             // DR15
    },
    /* US915 */
    {
        LW_DR(SF10, BW125),    // DR0
        LW_DR(SF9, BW125),     // DR1
        LW_DR(SF8, BW125),     // DR2
        LW_DR(SF7, BW125),     // DR3
        LW_DR(SF8, BW500),     // DR4
        LW_DR_RFU,             // DR5
        LW_DR_RFU,             // DR6
        LW_DR_RFU,             // DR7
        LW_DR(SF12, BW500),    // DR8
        LW_DR(SF11, BW500),    // DR9
        LW_DR(SF10, BW500),    // DR10
        LW_DR(SF9, BW500),     // DR11
        LW_DR(SF8, BW500),     // DR12
        LW_DR(SF7, BW500),     // DR13
        LW_DR_RFU,             // DR14
        LW_DR_RFU,             // DR15
    },
};

const int8_t lw_pow_tab[][16] = {
    /* EU868 */
    {
        20,
        14,
        11,
        8,
        5,
        2,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
    },
    /* US915 */
    {
        30,
        28,
        26,
        24,
        22,
        20,
        18,
        16,
        14,
        12,
        10,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
        LW_POW_RFU,
    },
};

const uint16_t lw_chmaskcntl_tab[][8]={
    {
        LW_CMC(0, 15),
        LW_CMC_RFU,
        LW_CMC_RFU,
        LW_CMC_RFU,
        LW_CMC_RFU,
        LW_CMC_RFU,
        LW_CMC_ALL_ON,
        LW_CMC_RFU,
    },
    {
        LW_CMC(0, 15),
        LW_CMC(16, 31),
        LW_CMC(32, 47),
        LW_CMC(48, 63),
        LW_CMC(64, 71),
        LW_CMC_RFU,
        LW_CMC_ALL_125KHZ_ON,
        LW_CMC_ALL_125KHZ_OFF,
    }
};

const lw_mtype_func_p lwp_mtye_func[8] = {
    lw_mtype_join_request,
    lw_mtype_join_accept,
    lw_mtype_msg_up,
    lw_mtype_msg_down,
    lw_mtype_cmsg_up,
    lw_mtype_cmsg_down,
    lw_mtype_rfu,
    lw_mtype_proprietary,
};

const char *lw_mtype_str[] = {
    "JOIN REQUEST",
    "JOIN ACCEPT",
    "UNCONFIRMED DATA UP",
    "UNCONFIRMED DATA DOWN",
    "CONFIRMED DATA UP",
    "CONFIRMED DATA DOWN",
    "RFU",
    "PROPRIETARY",
};

static int lw_log_flag = 1;

void lw_log_data(uint8_t *buf, int len)
{
    int i;

    uint8_t * str = malloc(len+1);
    str[len] = '\0';

    if(lw_log_flag){
        log_hex(LOG_NORMAL, buf, len, "DATA(HEX):");
    }
    for(i=0; i<len; i++){
        str[i] = buf[i];
        if(buf[i]<' ' || buf[i]>'~'){
            break;
        }
    }
    if(i==len){
        if(lw_log_flag){
            log_puts(LOG_NORMAL, "DATA(STR): %s", str);
        }
    }
    free(str);
}

int lw_get_dmsg(uint8_t *buf, int max_len)
{
    if( 0 == (lw_flag & LW_FLAG_BUF_OK) ){
        return LW_ERR_NOT_AVALAIBLE;
    }

    if(max_len<lw_buf.len){
        return -1;
    }

    memcpy(buf, lw_buf.buf, lw_buf.len);
    return lw_buf.len;
}

int lw_get_devnonce(lw_dnonce_t *dnonce)
{
    if( 0 == (lw_flag & LW_FLAG_DNONCE_OK) ){
        return LW_ERR_NOT_AVALAIBLE;
    }

    *dnonce = lw_dnonce;

    return 0;
}

int lw_get_appnonce(lw_anonce_t *anonce)
{
    if( 0 == (lw_flag & LW_FLAG_ANONCE_OK) ){
        return LW_ERR_NOT_AVALAIBLE;
    }

    *anonce = lw_anonce;

    return 0;
}

int lw_get_netid(lw_netid_t *netid)
{
    if( 0 == (lw_flag & LW_FLAG_NETID_OK) ){
        return LW_ERR_NOT_AVALAIBLE;
    }

    *netid = lw_netid;

    return 0;
}

int lw_log(int logflag)
{
    lw_log_flag = logflag;
    return lw_log_flag;
}

int lw_parse(uint8_t *buf, int len, lw_parse_key_t *pkey)
{
    lw_mhdr_t mhdr;
    int ret;

    lw_flag &= ~(LW_FLAG_BUF_OK);

    mhdr.data = buf[LW_MHDR];

    if(lw_log_flag){
        log_line();
        log_hex(LOG_NORMAL, buf, len, "MSG:");
    }

    if(mhdr.bits.major == LW_VERSION_MAJOR_R1){
        if(lw_log_flag){
            log_puts(LOG_NORMAL, "LoRaWAN R1");
        }
    }else{
        if(lw_log_flag){
            log_puts(LOG_NORMAL, "LoRaWAN version unknown");
        }
    }

    if(mhdr.bits.mtype>=LW_MTYPE_PROPRIETARY){
        return LW_ERR_CMD_UNKNOWN;
    }

    if(lw_log_flag){
        log_puts(LOG_NORMAL, "%s", lw_mtype_str[mhdr.bits.mtype]);
    }

    ret = lwp_mtye_func[mhdr.bits.mtype](buf, len, pkey);

    if(ret == LW_OK){
        lw_flag |= LW_FLAG_BUF_OK;
        if(lw_log_flag){
            log_hex(LOG_NORMAL, lw_buf.buf, lw_buf.len, "DMSG:");
        }
    }

    return ret;
}

int lw_mtype_join_request(uint8_t *buf, int len, lw_parse_key_t *pkey)
{
    lw_mic_t mic;
    lw_mic_t plmic;
    lw_key_t lw_key;
    int idx;

    lw_flag &= ~(LW_FLAG_DNONCE_OK);

    if(len != LW_JR_LEN){
        return LW_ERR_JOINR_LEN;
    }

    memcpy(plmic.buf, buf+len-4, 4);
    lw_key.aeskey = pkey->appkey;
    lw_key.in = buf;
    lw_key.len = len-4;
    lw_join_mic(&mic, &lw_key);
    if(mic.data == plmic.data){
        if(lw_log_flag){
            log_puts(LOG_NORMAL, "Join Request MIC is OK");
        }
    }else{
        if(lw_log_flag){
            log_puts(LOG_NORMAL, "Join Request MIC is ERROR");
        }
    }

    if(mic.data != plmic.data){
        if(lw_log_flag){
           log_puts(LOG_NORMAL, "MIC is ERROR");
        }
        return LW_ERR_MIC;
    }

    if(lw_log_flag){
        log_puts(LOG_NORMAL, "MIC is OK [ %02X %02X %02X %02X ]", mic.buf[0], mic.buf[1], mic.buf[2], mic.buf[3]);
        idx = LW_JR_OFF_APPEUI;
        log_puts(LOG_NORMAL, "APPEUI: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", buf[idx+7], buf[idx+6], buf[idx+5], buf[idx+4], buf[idx+3], buf[idx+2], buf[idx+1], buf[idx+0]);
        idx = LW_JR_OFF_DEVEUI;
        log_puts(LOG_NORMAL, "DEVEUI: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", buf[idx+7], buf[idx+6], buf[idx+5], buf[idx+4], buf[idx+3], buf[idx+2], buf[idx+1], buf[idx+0]);
        idx = LW_JR_OFF_DEVNONCE;
        log_puts(LOG_NORMAL, "DEVNONCE: 0x%02X%02X", buf[idx+1], buf[idx]);
    }

    memcpy(lw_buf.buf, buf, len);
    lw_buf.len = len;

    /** Save DEVNONCE to global variable */
    memcpy(lw_dnonce.buf, buf+LW_JR_OFF_DEVNONCE, 2);

    lw_flag |= LW_FLAG_DNONCE_OK;

    return LW_OK;
}

int lw_mtype_join_accept(uint8_t *buf, int len, lw_parse_key_t *pkey)
{
    lw_mic_t mic;
    lw_mic_t plmic;
    lw_key_t lw_key;
    lw_skey_seed_t lw_skey_seed;
    uint8_t *out;
    int pl_len;
    int idx;

    lw_flag &= ~(LW_FLAG_ANONCE_OK);
    lw_flag &= ~(LW_FLAG_NETID_OK);

    if( (len != LW_JA_LEN) && (len != LW_JA_LEN_EXT) ){
        return LW_ERR_JOINA_LEN;
    }

    out = malloc(len);
    if(out == NULL){
        return LW_ERR_MALLOC;
    }

    if(lw_log_flag){
        //log_hex(LOG_DEBUG, buf, len, "DEBUG:");
    }

    lw_key.aeskey = pkey->appkey;
    lw_key.in = buf+1;
    lw_key.len = len-1;
    out[0] = buf[0];
    pl_len = lw_join_decrypt(out+1, &lw_key);

    if(pl_len>0){
        if(lw_log_flag){
            log_puts(LOG_NORMAL, "Join accept encrypted payload:(%d)", len);
            log_hex(LOG_NORMAL, buf, len, 0);
            log_puts(LOG_NORMAL, "Join accept decrypted payload:(%d)", len);
            log_hex(LOG_NORMAL, out, len, 0);
        }
        memcpy(plmic.buf, out+len-4, 4);
        lw_key.aeskey = pkey->appkey;
        lw_key.in = out;
        lw_key.len = len-4;
        lw_join_mic(&mic, &lw_key);
        if(mic.data == plmic.data){
            if(lw_log_flag){
                log_puts(LOG_NORMAL,"JoinAccept MIC is OK");
            }
        }else{
            if(lw_log_flag){
                log_puts(LOG_NORMAL,"JoinAccept MIC is ERROR");
            }
        }
    }

    lw_skey_seed.aeskey = pkey->appkey;
    memcpy(lw_skey_seed.anonce.buf, out+LW_JA_OFF_APPNONCE ,3);
    lw_skey_seed.dnonce = lw_dnonce;
    memcpy(lw_skey_seed.netid.buf, out+LW_JA_OFF_NETID ,3);
    lw_get_skeys(lw_nwkskey, lw_appskey, &lw_skey_seed);

    if(lw_log_flag){
        idx = LW_JA_OFF_APPNONCE;
        log_puts(LOG_NORMAL, "APPNONCE: 0x%02X%02X%02X", out[idx+2], out[idx+1], out[idx+0]);
        idx = LW_JA_OFF_NETID;
        log_puts(LOG_NORMAL, "NETID: 0x%02X%02X%02X",out[idx+2], out[idx+1], out[idx+0]);
        idx = LW_JA_OFF_DEVADDR;
        log_puts(LOG_NORMAL, "DEVADDR: %02X:%02X:%02X:%02X", out[idx+3], out[idx+2], out[idx+1], out[idx+0]);
        idx = LW_JA_OFF_DLSET;
        log_puts(LOG_NORMAL, "RX2DataRate: %d", out[idx]&0x0F);
        log_puts(LOG_NORMAL, "RX1DRoffset: %d", (out[idx]>>4)&0x07);
    }
    if(len == LW_JA_LEN_EXT){
        idx = LW_JA_OFF_CFLIST;
        if(lw_log_flag){
            log_hex(LOG_NORMAL, out+idx, 16, "CFList:");
        }
    }

    if(lw_log_flag){
        log_hex(LOG_NORMAL, lw_nwkskey, LW_KEY_LEN, "NWKSKEY:");
        log_hex(LOG_NORMAL, lw_appskey, LW_KEY_LEN, "APPSKEY:");
    }
    lw_buf.len = len;
    memcpy(lw_buf.buf, out, lw_buf.len);

    /** Save APPNONCE and NETID */
    lw_anonce = lw_skey_seed.anonce;
    lw_netid = lw_skey_seed.netid;

    free(out);

    lw_flag |= LW_FLAG_ANONCE_OK;
    lw_flag |= LW_FLAG_NETID_OK;
    return LW_OK;
}

int lw_mtype_msg_up(uint8_t *msg, int len, lw_parse_key_t *pkey)
{
    lw_mic_t mic;
    lw_mic_t plmic;
    lw_key_t lw_key;

    lw_ul_fctrl_t fctrl;
    int16_t port;
    int pl_len;
    int pl_index;
    uint8_t out[255];

    /** calculate MIC */
    memcpy(plmic.buf, msg+len-4, 4);
    lw_key.aeskey = pkey->nwkskey;
    lw_key.in = msg;
    lw_key.len = len-4;
    lw_key.link = LW_UPLINK;
    memcpy(lw_key.devaddr.buf, msg+LW_DATA_OFF_DEVADDR, 4);
    lw_key.fcnt32 = ((uint32_t)msg[LW_DATA_OFF_FCNT+1]<<8) + msg[LW_DATA_OFF_FCNT];
    lw_msg_mic(&mic, &lw_key);

    if(mic.data != plmic.data){
        if(lw_log_flag){
            log_puts(LOG_WARN, "MIC is ERROR");
        }
        return LW_ERR_MIC;
    }
    if(lw_log_flag){
        log_puts(LOG_NORMAL, "MIC is OK [ %02X %02X %02X %02X ]", mic.buf[0], mic.buf[1], mic.buf[2], mic.buf[3]);
        log_puts(LOG_NORMAL, "DEVADDR: %02X:%02X:%02X:%02X", lw_key.devaddr.buf[3], lw_key.devaddr.buf[2], lw_key.devaddr.buf[1], lw_key.devaddr.buf[0]);
    }

    fctrl.data = msg[LW_DATA_OFF_FCTRL];

    if(lw_log_flag){
        log_puts(LOG_NORMAL, "ADR: %d, ADRACKREQ: %d, ACK %d", fctrl.bits.adr, fctrl.bits.adrackreq, fctrl.bits.ack);
        if(fctrl.bits.classb){
            log_puts(LOG_NORMAL, "Class B");
        }
    }

    if( len > (8 + 4 + fctrl.bits.foptslen) ){

        /** Test Normal Message Decrypt */
        port = msg[LW_DATA_OFF_FOPTS + fctrl.bits.foptslen];
        if(port == 0){
            lw_key.aeskey = pkey->nwkskey;
        }else{
            lw_key.aeskey = pkey->appskey;
        }
        pl_index = LW_DATA_OFF_FOPTS + fctrl.bits.foptslen + 1;
        pl_len  = len - 4 - pl_index;
        lw_key.in = msg + pl_index;
        lw_key.len = pl_len;
        pl_len = lw_encrypt(out, &lw_key);
        if(pl_len<=0){
            return LW_ERR_DECRYPT;
        }

        /** copy decrypted payload to lw_buf */
        memcpy(lw_buf.buf, msg, pl_index);        // until port, pl_index equals length of MHDR+FHDR+FPOR
        memcpy(lw_buf.buf + pl_index, out, pl_len);   // payload
        memcpy(lw_buf.buf + len - 4, mic.buf, 4); // mic
        lw_buf.len = len;
    }else{
        port = -1;
        if(lw_log_flag){
            log_puts(LOG_NORMAL, "No Port and FRMPayload field in message");
        }
    }

    if(lw_log_flag){
        if(port>=0){
            log_puts(LOG_NORMAL, "PORT: %d", port);
        }else{
            log_puts(LOG_NORMAL, "PORT: NONE");
        }
    }
    if(lw_log_flag){
        log_puts(LOG_NORMAL, "FCNT: %d [0x%X]", lw_key.fcnt32, lw_key.fcnt32);
    }

    if(fctrl.bits.foptslen != 0 && port == 0){
        //log_puts(LOG_NORMAL, "[ERROR] PORT ZERO WITH FOPTS");
        return LW_ERR_FOPTS_PORT0;
    }else if(fctrl.bits.foptslen != 0 && port != 0){
        if(lw_maccmd(msg[LW_MHDR], msg+LW_DATA_OFF_FOPTS, fctrl.bits.foptslen) < 0){
            return LW_ERR_MACCMD;
        }
        if(port>0){
            lw_log_data(lw_buf.buf + pl_index, pl_len);
        }
    }else if(port == 0){
        if(lw_maccmd(msg[LW_MHDR], lw_buf.buf + pl_index, pl_len) < 0){
            return LW_ERR_MACCMD;
        }
    }else if(port>0){
        lw_log_data(lw_buf.buf + pl_index, pl_len);
    }

    return LW_OK;
}

int lw_mtype_cmsg_up(uint8_t *msg, int len, lw_parse_key_t *pkey)
{
    return lw_mtype_msg_up(msg, len, pkey);
}

int lw_mtype_msg_down(uint8_t *msg, int len, lw_parse_key_t *pkey)
{
    lw_mic_t mic;
    lw_mic_t plmic;
    lw_key_t lw_key;

    lw_dl_fctrl_t fctrl;
    int16_t port;
    int pl_len;
    int pl_index;

    /** calculate MIC */
    memcpy(plmic.buf, msg+len-4, 4);
    lw_key.aeskey = pkey->nwkskey;
    lw_key.in = msg;
    lw_key.len = len-4;
    lw_key.link = LW_DOWNLINK;
    memcpy(lw_key.devaddr.buf, msg+LW_DATA_OFF_DEVADDR, 4);
    lw_key.fcnt32 = ((uint32_t)msg[LW_DATA_OFF_FCNT+1]<<8) + msg[LW_DATA_OFF_FCNT];
    lw_msg_mic(&mic, &lw_key);

    if(mic.data != plmic.data){
        if(lw_log_flag){
            log_puts(LOG_WARN, "MIC is ERROR");
        }
        return LW_ERR_MIC;
    }

    if(lw_log_flag){
        log_puts(LOG_NORMAL, "MIC is OK [ %02X %02X %02X %02X ]", mic.buf[0], mic.buf[1], mic.buf[2], mic.buf[3]);
        log_puts(LOG_NORMAL, "DEVADDR: %02X:%02X:%02X:%02X", lw_key.devaddr.buf[3], lw_key.devaddr.buf[2], lw_key.devaddr.buf[1], lw_key.devaddr.buf[0]);
    }

    fctrl.data = msg[LW_DATA_OFF_FCTRL];

    if(lw_log_flag){
        log_puts(LOG_NORMAL, "ADR: %d, ADRACKREQ: %d, ACK %d", fctrl.bits.adr, fctrl.bits.adrackreq, fctrl.bits.ack);
        if(fctrl.bits.fpending){
            log_puts(LOG_NORMAL, "FPENDING is on");
        }
    }

    if( len > (8 + 4 + fctrl.bits.foptslen) ){

        /** Test Normal Message Decrypt */
        port = msg[LW_DATA_OFF_FOPTS + fctrl.bits.foptslen];
        if(port == 0){
            lw_key.aeskey = pkey->nwkskey;
        }else{
            lw_key.aeskey = pkey->appskey;
        }
        pl_index = LW_DATA_OFF_FOPTS + fctrl.bits.foptslen + 1;
        pl_len  = len - 4 - pl_index;
        lw_key.in = msg + pl_index;
        lw_key.len = pl_len;
        uint8_t *out = malloc(lw_key.len);
        pl_len = lw_encrypt(out, &lw_key);
        if(pl_len<=0){
            free(out);
            return LW_ERR_DECRYPT;
        }

        /** copy decrypted payload to lw_buf */
        memcpy(lw_buf.buf, msg, pl_index);        // until port, pl_index equals length of MHDR+FHDR+FPOR
        memcpy(lw_buf.buf + pl_index, out, pl_len);   // payload
        memcpy(lw_buf.buf + len - 4, mic.buf, 4); // mic
        lw_buf.len = len;

        free(out);
    }else{
        port = -1;
        memcpy(lw_buf.buf, msg, len);
        if(lw_log_flag){
            log_puts(LOG_NORMAL, "No Port and FRMPayload field in message");
        }
    }

    if(lw_log_flag){
        if(port>=0){
            log_puts(LOG_NORMAL, "PORT: %d", port);
        }
        log_puts(LOG_NORMAL, "FCNT: %d [0x%X]", lw_key.fcnt32, lw_key.fcnt32);
    }
    if(fctrl.bits.foptslen != 0 && port == 0){
        //log_puts(LOG_NORMAL, "[ERROR] PORT ZERO WITH FOPTS");
        return LW_ERR_FOPTS_PORT0;
    }else if(fctrl.bits.foptslen != 0 && port != 0){
        if(lw_maccmd(msg[LW_MHDR], msg+LW_DATA_OFF_FOPTS, fctrl.bits.foptslen) < 0){
            return LW_ERR_MACCMD;
        }
        if(port>0){
            lw_log_data(lw_buf.buf + pl_index, pl_len);
        }
    }else if(port == 0){
        if(lw_maccmd(msg[LW_MHDR], lw_buf.buf + pl_index, pl_len) < 0){
            return LW_ERR_MACCMD;
        }
    }else if(port>0){
        lw_log_data(lw_buf.buf + pl_index, pl_len);
    }

    return LW_OK;
}

int lw_mtype_cmsg_down(uint8_t *msg, int len, lw_parse_key_t *pkey)
{
    return lw_mtype_msg_down(msg, len, pkey);
}

int lw_mtype_rfu(uint8_t *msg, int len, lw_parse_key_t *pkey)
{
    return LW_OK;
}

int lw_mtype_proprietary(uint8_t *msg, int len, lw_parse_key_t *pkey)
{
    return LW_OK;
}

int lw_set_band(lw_band_t band)
{
    if(band > LW_BAND_CUSTOM){
        return LW_ERR_BAND;
    }

    lw_band = band;

    return LW_OK;
}

const char *lw_maccmd_str(uint8_t mtype, uint8_t cmd)
{
    if( (mtype == LW_MTYPE_MSG_UP) || (mtype == LW_MTYPE_CMSG_UP) ){
        switch(cmd){
            // Class A
        case LW_MCMD_LCHK_REQ:
            return "LinkCheckReq";
        case LW_MCMD_LADR_ANS:
            return "LinkADRAns";
        case LW_MCMD_DCAP_ANS:
            return "DutyCycleAns";
        case LW_MCMD_DN2P_ANS:
            return "RXParamSetupAns";
        case LW_MCMD_DEVS_ANS:
            return "DevStatusAns";
        case LW_MCMD_SNCH_ANS:
            return "NewChannelAns";
        case LW_MCMD_RXTS_ANS:
            return "RXTimingSetupAns";
            //Class B
        case LW_MCMD_PING_IND:
            break;
        case LW_MCMD_PING_ANS:
            break;
        case LW_MCMD_BCNI_REQ:
            break;
        }
    }else if( (mtype == LW_MTYPE_MSG_DOWN) || (mtype == LW_MTYPE_CMSG_DOWN) ){
        switch(cmd){
            // Class A
        case LW_MCMD_LCHK_ANS:
            return "LinkCheckAns";
        case LW_MCMD_LADR_REQ:
            return "LinkADRReq";
        case LW_MCMD_DCAP_REQ:
            return "DutyCycleReq";
        case LW_MCMD_DN2P_REQ:
            return "RXParamSetupReq";
        case LW_MCMD_DEVS_REQ:
            return "DevStatusReq";
        case LW_MCMD_SNCH_REQ:
            return "NewChannelReq";
        case LW_MCMD_RXTS_REQ:
            return "RXTimingSetupReq";
            //Class B
        case LW_MCMD_PING_SET:
            break;
        case LW_MCMD_BCNI_ANS:
            break;
        }
    }

    return NULL;
}

void lw_no_pl(void)
{
    if(lw_log_flag){
        log_puts(LOG_NORMAL, "No MAC command payload");
    }
}

int lw_maccmd(uint8_t mac_header, uint8_t *opts, int len)
{
    lw_mhdr_t mhdr;
    uint16_t ChMask;
    uint8_t dr;
    uint8_t power;
    uint16_t chmaskcntl;
    uint8_t rx1drofst;
    uint8_t rx2dr;
    uint32_t freq;
    union {
        uint8_t data;
        struct{
            int8_t margin           :6;
        }bits;
    }dev_sta_margin;

    lw_band_t band;

    int i;

    mhdr.data = mac_header;

    if(lw_band != LW_BAND_US915){
        band = LW_BAND_US915;
    }else{
        band = LW_BAND_EU868;
    }

    // Traverse all possible commands, if any of them is invalid terminate and return error
    i=0;
    while(i<len){
        if( (mhdr.bits.mtype == LW_MTYPE_MSG_UP) || (mhdr.bits.mtype == LW_MTYPE_CMSG_UP) ){
            switch(opts[i]){
                // Class A
            case LW_MCMD_LCHK_REQ:
                if((len-i+1) < LW_MCMD_LCHK_REQ_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_LCHK_REQ_LEN;
                break;
            case LW_MCMD_LADR_ANS:
                if((len-i+1) < LW_MCMD_LADR_ANS_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_LADR_ANS_LEN;
                break;
            case LW_MCMD_DCAP_ANS:
                if((len-i+1) < LW_MCMD_DCAP_ANS_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_DCAP_ANS_LEN;
                break;
            case LW_MCMD_DN2P_ANS:
                if((len-i+1) < LW_MCMD_DN2P_ANS_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_DN2P_ANS_LEN;
                break;
            case LW_MCMD_DEVS_ANS:
                if((len-i+1) < LW_MCMD_DEVS_ANS_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_DEVS_ANS_LEN;
                break;
            case LW_MCMD_SNCH_ANS:
                if((len-i+1) < LW_MCMD_SNCH_ANS_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_SNCH_ANS_LEN;
                break;
            case LW_MCMD_RXTS_ANS:
                if((len-i+1) < LW_MCMD_RXTS_ANS_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_RXTS_ANS_LEN;
                break;
            //Class B
            case LW_MCMD_PING_IND:
                if((len-i+1) < 1){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=1;
                break;
            case LW_MCMD_PING_ANS:
                if((len-i+1) < 1){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=1;
                break;
            case LW_MCMD_BCNI_REQ:
                if((len-i+1) < 1){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=1;
                break;
            default:
                return LW_ERR_MACCMD_LEN;
            }
        }else if( (mhdr.bits.mtype == LW_MTYPE_MSG_DOWN) || (mhdr.bits.mtype == LW_MTYPE_CMSG_DOWN) ){
            switch(opts[i]){
            // Class A
            case LW_MCMD_LCHK_ANS:
                if((len-i+1) < LW_MCMD_LCHK_ANS_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_LCHK_ANS_LEN;
                break;
            case LW_MCMD_LADR_REQ:
                if((len-i+1) < LW_MCMD_LADR_REQ_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_LADR_REQ_LEN;
                break;
            case LW_MCMD_DCAP_REQ:
                if((len-i+1) < LW_MCMD_DCAP_REQ_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_DCAP_REQ_LEN;
                break;
            case LW_MCMD_DN2P_REQ:
                if((len-i+1) < LW_MCMD_DN2P_REQ_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_DN2P_REQ_LEN;
                break;
            case LW_MCMD_DEVS_REQ:
                if((len-i+1) < LW_MCMD_DEVS_REQ_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_DEVS_REQ_LEN;
                break;
            case LW_MCMD_SNCH_REQ:
                if((len-i+1) < LW_MCMD_SNCH_REQ_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_SNCH_REQ_LEN;
                break;
            case LW_MCMD_RXTS_REQ:
                if((len-i+1) < LW_MCMD_RXTS_REQ_LEN){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=LW_MCMD_RXTS_REQ_LEN;
                break;
                //Class B
            case LW_MCMD_PING_SET:
                if((len-i+1) < 1){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=1;
                break;
            case LW_MCMD_BCNI_ANS:
                if((len-i+1) < 1){
                    return LW_ERR_MACCMD_LEN;
                }
                i+=1;
                break;
            default:
                return LW_ERR_MACCMD_LEN;
            }
        }else{
            return LW_ERR_MACCMD;
        }
    }

    if(0  == lw_log_flag){
        return LW_OK;
    }
    log_hex(LOG_NORMAL, opts, len, "MACCMD:");
    i=0;
    while(i<len){
        if(lw_log_flag){
            log_puts(LOG_NORMAL, "MACCMD ( %s )", lw_maccmd_str(mhdr.bits.mtype, opts[i]));
        }
        if( (mhdr.bits.mtype == LW_MTYPE_MSG_UP) || (mhdr.bits.mtype == LW_MTYPE_CMSG_UP) ){
            switch(opts[i]){
                // Class A
            case LW_MCMD_LCHK_REQ:
                i+=LW_MCMD_LCHK_REQ_LEN;
                lw_no_pl();
                break;
            case LW_MCMD_LADR_ANS:
                i+=LW_MCMD_LADR_ANS_LEN;
                log_puts(LOG_NORMAL, "Status: 0x%02X", opts[i+1]);
                log_puts(LOG_NORMAL, "Channel mask %s", (opts[i+1]&0x01)?"ACK":"NACK");
                log_puts(LOG_NORMAL, "Data rate %s", (opts[i+1]&0x02)?"ACK":"NACK");
                log_puts(LOG_NORMAL, "Power %s", (opts[i+1]&0x04)?"ACK":"NACK");
                break;
            case LW_MCMD_DCAP_ANS:
                i+=LW_MCMD_DCAP_ANS_LEN;
                lw_no_pl();
                break;
            case LW_MCMD_DN2P_ANS:
                i+=LW_MCMD_DN2P_ANS_LEN;
                log_puts(LOG_NORMAL, "Status: 0x%02X", opts[i+1]);
                log_puts(LOG_NORMAL, "Channel %s", (opts[i+1]&0x01)?"ACK":"NACK");
                log_puts(LOG_NORMAL, "RXWIN2 %s", (opts[i+1]&0x02)?"ACK":"NACK");
                log_puts(LOG_NORMAL, "RX1DRoffset %s", (opts[i+1]&0x04)?"ACK":"NACK");
                break;
            case LW_MCMD_DEVS_ANS:
                i+=LW_MCMD_DEVS_ANS_LEN;
                if(opts[i+1] == 0){
                    log_puts(LOG_NORMAL, "Battery: %d (External Powered)", opts[i+1]);
                }else if(opts[i+1] == 255){
                    log_puts(LOG_NORMAL, "Battery: %d (Unknown)", opts[i+1]);
                }else{
                    log_puts(LOG_NORMAL, "Battery: %d (%.1f%%)", opts[i+1], 1.0*opts[i+1]/255);
                }
                dev_sta_margin.data = opts[i+2];
                log_puts(LOG_NORMAL, "Margin: %d", dev_sta_margin.bits.margin);

                break;
            case LW_MCMD_SNCH_ANS:
                i+=LW_MCMD_SNCH_ANS_LEN;
                log_puts(LOG_NORMAL, "Status: 0x%02X", opts[i+1]);
                log_puts(LOG_NORMAL, "Channel %s", (opts[i+1]&0x01)?"ACK":"NACK");
                log_puts(LOG_NORMAL, "DataRate %s", (opts[i+1]&0x02)?"ACK":"NACK");
                break;
            case LW_MCMD_RXTS_ANS:
                i+=LW_MCMD_RXTS_ANS_LEN;
                lw_no_pl();
                break;
            //Class B
            case LW_MCMD_PING_IND:
                i+=1;
                lw_no_pl();
                break;
            case LW_MCMD_PING_ANS:
                i+=1;
                lw_no_pl();
                break;
            case LW_MCMD_BCNI_REQ:
                i+=1;
                lw_no_pl();
                break;
            }
        }else if( (mhdr.bits.mtype == LW_MTYPE_MSG_DOWN) || (mhdr.bits.mtype == LW_MTYPE_CMSG_DOWN) ){
            switch(opts[i]){
            // Class A
            case LW_MCMD_LCHK_ANS:
                i+=LW_MCMD_LCHK_ANS_LEN;
                if(opts[i+1] == 255){
                    log_puts(LOG_NORMAL, "Margin: %d (RFU)", opts[i+1]);
                }else{
                    log_puts(LOG_NORMAL, "Margin: %ddB", opts[i+1]);
                }
                log_puts(LOG_NORMAL, "GwCnt: %d", opts[i+2]);
                break;
            case LW_MCMD_LADR_REQ:
                i+=LW_MCMD_LADR_REQ_LEN;
                dr = lw_dr_tab[band][opts[i+1]>>4];
                power = lw_pow_tab[band][opts[i+1]&0x0F];
                chmaskcntl = lw_chmaskcntl_tab[band][(opts[i+4]>>4)&0x07];
                ChMask = opts[i+2] + (((uint16_t)opts[i+3])<<8);
                if(power == LW_POW_RFU){
                    log_puts(LOG_NORMAL, "TXPower: %d (RFU)", opts[i+1]&0x0F);
                }else{
                    log_puts(LOG_NORMAL, "TXPower: %d (%ddBm)", opts[i+1]&0x0F, power);
                }
                if(dr == LW_DR_RFU){
                    log_puts(LOG_NORMAL, "DataRate: DR%d (RFU)", opts[i+1]>>4);
                }else if( (dr&0x0F) == FSK){
                    log_puts(LOG_NORMAL, "DataRate: DR%d (FSK)", opts[i+1]>>4);
                }else{
                    log_puts(LOG_NORMAL, "DataRate: DR%d (SF%d/BW%dKHz)", opts[i+1]>>4, dr&0x0F, (int)(125*pow(2,dr>>4)));
                }
                log_puts(LOG_NORMAL, "ChMask: 0x%04X", ChMask);
                log_puts(LOG_NORMAL, "NbRep: %d", opts[i+4]&0x0F);
                switch(chmaskcntl){
                case LW_CMC_RFU:
                    log_puts(LOG_NORMAL, "ChMaskCntl: %d (RFU)", (opts[i+4]>>4)&0x07);
                    break;
                case LW_CMC_ALL_ON:
                    log_puts(LOG_NORMAL, "ChMaskCntl: %d (EU868 All on)", (opts[i+4]>>4)&0x07);
                    break;
                case LW_CMC_ALL_125KHZ_ON:
                    log_puts(LOG_NORMAL, "ChMaskCntl: %d, All 125KHz channels on, ChMask applies to 64 ~ 71", (opts[i+4]>>4)&0x07);
                    break;
                case LW_CMC_ALL_125KHZ_OFF:
                    log_puts(LOG_NORMAL, "ChMaskCntl: %d, All 125KHz channels off, ChMask applies to 64 ~ 71", (opts[i+4]>>4)&0x07);
                    break;
                default:
                    log_puts(LOG_NORMAL, "ChMaskCntl: %d, ChMask applies to %d ~ %d", (opts[i+4]>>4)&0x07, chmaskcntl&0x00FF, chmaskcntl>>8);
                    break;
                }
                break;
            case LW_MCMD_DCAP_REQ:
                i+=LW_MCMD_DCAP_REQ_LEN;
                if(opts[i+1] == 255){
                    log_puts(LOG_NORMAL, "MaxDCycle: %d(Off)", opts[i+1]);
                }else if(opts[i+1]<16){
                    log_puts(LOG_NORMAL, "MaxDCycle: %d (%.2f%%)", opts[i+1], 100.0/pow(2,opts[i+1]));
                }else{
                    log_puts(LOG_NORMAL, "MaxDCycle: %d(RFU)", opts[i+1]);
                }
                break;
            case LW_MCMD_DN2P_REQ:
                i+=LW_MCMD_DN2P_REQ_LEN;
                rx1drofst = (opts[i+1]>>4) & 0x07;
                rx2dr = lw_dr_tab[band][opts[i+1] & 0x0F];
                freq = (opts[i+2]) | ((uint32_t)opts[i+3]<<8) | ((uint32_t)opts[i+4]<<16);
                freq *= 100;
                log_puts(LOG_NORMAL, "RX1DROffset: %d", rx1drofst);
                if(rx2dr == LW_DR_RFU){
                    log_puts(LOG_NORMAL, "RX2DataRate: DR%d (RFU)", opts[i+1] & 0x0F);
                }else if( (rx2dr&0x0F) == FSK){
                    log_puts(LOG_NORMAL, "RX2DataRate: DR%d (FSK)", opts[i+1] & 0x0F);
                }else{
                    log_puts(LOG_NORMAL, "RX2DataRate: DR%d (SF%d/BW%dKHz)", opts[i+1] & 0x0F, rx2dr&0x0F, (int)(125*pow(2,rx2dr>>4)));
                }
                if(freq < 100000000){
                    log_puts(LOG_NORMAL, "Freq: %d (RFU <100MHz)", freq);
                }else{
                    log_puts(LOG_NORMAL, "Freq: %d", freq);
                }
                break;
            case LW_MCMD_DEVS_REQ:
                i+=LW_MCMD_DEVS_REQ_LEN;
                lw_no_pl();
                break;
            case LW_MCMD_SNCH_REQ:
                i+=LW_MCMD_SNCH_REQ_LEN;
                freq = (opts[i+2]) | ((uint32_t)opts[i+3]<<8) | ((uint32_t)opts[i+4]<<16);
                freq *= 100;
                log_puts(LOG_NORMAL, "ChIndex: %d", opts[i+1]);
                if(freq < 100000000){
                    log_puts(LOG_NORMAL, "Freq: %d (RFU <100MHz)", freq);
                }else{
                    log_puts(LOG_NORMAL, "Freq: %d", freq);
                }
                log_puts(LOG_NORMAL, "DrRange: 0x%02X (DR%d ~ DR%d)", opts[i+5], opts[i+5]&0x0F, opts[i+5]>>4);
                break;
            case LW_MCMD_RXTS_REQ:
                i+=LW_MCMD_RXTS_REQ_LEN;
                if((opts[i+1]&0x0F) == 0){
                    log_puts(LOG_NORMAL, "Del: %ds", (opts[i+1]&0x0F)+1);
                }else{
                    log_puts(LOG_NORMAL, "Del: %ds", opts[i+1]&0x0F);
                }
                break;
                //Class B
            case LW_MCMD_PING_SET:
                i+=1;
                lw_no_pl();
                break;
            case LW_MCMD_BCNI_ANS:
                i+=1;
                lw_no_pl();
                break;
            }
        }
    }

    return LW_OK;
}

uint8_t *lw_write_dw(uint8_t *output, uint32_t input)
{
	uint8_t* ptr = output;

	*(ptr++) = (uint8_t)(input), input >>= 8;
	*(ptr++) = (uint8_t)(input), input >>= 8;
	*(ptr++) = (uint8_t)(input), input >>= 8;
	*(ptr++) = (uint8_t)(input);

	return ptr;
}

void lw_msg_mic(lw_mic_t* mic, lw_key_t *key)
{
    uint8_t b0[LW_KEY_LEN];
    memset(b0, 0 , LW_KEY_LEN);
    b0[0] = 0x49;
    b0[5] = key->link;

    lw_write_dw(b0+6, key->devaddr.data);
    lw_write_dw(b0+10, key->fcnt32);
    b0[15] = (uint8_t)key->len;

	AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->aeskey);

	AES_CMAC_Update(&cmacctx, b0, LW_KEY_LEN);
	AES_CMAC_Update(&cmacctx, key->in, key->len);

	uint8_t temp[LW_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);

	memcpy(mic->buf, temp, LW_MIC_LEN);
}

void lw_join_mic(lw_mic_t* mic, lw_key_t *key)
{
    AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->aeskey);

	AES_CMAC_Update(&cmacctx, key->in, key->len);

	uint8_t temp[LW_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);

	memcpy(mic->buf, temp, LW_MIC_LEN);
}

/** Use to generate JoinAccept Payload */
int lw_join_encrypt(uint8_t *out, lw_key_t *key)
{
    if((key->len == 0) || (key->len%LW_KEY_LEN != 0)){
        if(lw_log_flag){
            log_puts(LOG_ERROR, "lw_ja_encrypt input length error [%d]", key->len);
        }
        return -1;
    }

    aes_context aesContext;

	aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

    // Check if optional CFList is included
    int i;
    for(i=0; i<key->len; i+=LW_KEY_LEN){
        aes_decrypt( key->in + i, out + i, &aesContext );
    }

    return key->len;
}

/** Use to decrypt JoinAccept Payload */
int lw_join_decrypt(uint8_t *out, lw_key_t *key)
{
    if((key->len == 0) || (key->len%LW_KEY_LEN != 0)){
        if(lw_log_flag){
            log_puts(LOG_ERROR, "lw_ja_encrypt input length error [%d]", key->len);
        }
        return -1;
    }

    aes_context aesContext;

	aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

    // Check if optional CFList is included
    int i;
    for(i=0; i<key->len; i+=LW_KEY_LEN){
        aes_encrypt( key->in + i, out + i, &aesContext );
    }

    return key->len;
}

void lw_block_xor(uint8_t const l[], uint8_t const r[], uint8_t out[], uint16_t bytes)
{
	uint8_t const* lptr = l;
	uint8_t const* rptr = r;
	uint8_t* optr = out;
	uint8_t const* const end = out + bytes;

	for (;optr < end; lptr++, rptr++, optr++)
		*optr = *lptr ^ *rptr;
}

int lw_encrypt(uint8_t *out, lw_key_t *key)
{
    if (key->len == 0)
		return -1;

	uint8_t A[LW_KEY_LEN];

	uint16_t const over_hang_bytes = key->len%LW_KEY_LEN;
    int blocks = key->len/LW_KEY_LEN + 1;

	memset(A, 0, LW_KEY_LEN);

	A[0] = 0x01; //encryption flags
	A[5] = key->link;

	lw_write_dw(A+6, key->devaddr.data);
	lw_write_dw(A+10, key->fcnt32);

	uint8_t const* blockInput = key->in;
	uint8_t* blockOutput = out;
	uint16_t i;
	for(i = 1; i <= blocks; i++, blockInput += LW_KEY_LEN, blockOutput += LW_KEY_LEN){
		A[15] = (uint8_t)(i);

		aes_context aesContext;
		aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

		uint8_t S[LW_KEY_LEN];
		aes_encrypt(A, S, &aesContext);

		uint16_t bytes_to_encrypt;
		if ((i < blocks) || (over_hang_bytes == 0))
			bytes_to_encrypt = LW_KEY_LEN;
		else
			bytes_to_encrypt = over_hang_bytes;

		lw_block_xor(S, blockInput, blockOutput, bytes_to_encrypt);
	}
	return key->len;
}

void lw_get_skeys(uint8_t *nwkskey, uint8_t *appskey, lw_skey_seed_t *seed)
{
    aes_context aesContext;
    uint8_t b[LW_KEY_LEN];

    memset(&aesContext, 0, sizeof(aesContext));
    memset(b, 0, LW_KEY_LEN);
    memcpy(b+1, seed->anonce.buf, 3);
    memcpy(b+4, seed->netid.buf, 3);
    memcpy(b+7, seed->dnonce.buf, 2);

    b[0] = 0x01;
	aes_set_key(seed->aeskey, LW_KEY_LEN, &aesContext);
    aes_encrypt( b, nwkskey, &aesContext );

    b[0] = 0x02;
	aes_set_key(seed->aeskey, LW_KEY_LEN, &aesContext);
    aes_encrypt( b, appskey, &aesContext );
}
