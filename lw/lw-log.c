#include "lw-log.h"
#include "lw.h"
#include "log.h"
#include "math.h"

extern const uint8_t lw_dr_tab[][16];
extern const int8_t lw_pow_tab[][16];
extern const uint16_t lw_chmaskcntl_tab[][8];
extern lw_node_t *lw_node;
extern lw_band_t lw_band;

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
typedef struct{
    uint8_t cmd;
    char *str;
}lw_maccmd_str_t;

const lw_maccmd_str_t lw_node_maccmd_str[] = {
    { MOTE_MAC_LINK_CHECK_REQ,          "LinkCheckReq" },
    { MOTE_MAC_LINK_ADR_ANS,            "LinkADRAns" },
    { MOTE_MAC_DUTY_CYCLE_ANS,          "DutyCycleAns" },
    { MOTE_MAC_RX_PARAM_SETUP_ANS,      "RXParamSetupAns" },
    { MOTE_MAC_DEV_STATUS_ANS,          "DevStatusAns" },
    { MOTE_MAC_NEW_CHANNEL_ANS,         "NewChannelAns" },
    { MOTE_MAC_RX_TIMING_SETUP_ANS,     "RXTimingSetupAns" },
    { MOTE_MAC_TX_PARAM_SETUP_ANS,      "TxParamSetupAns" },
    { MOTE_MAC_DL_CHANNEL_ANS,          "DlChannelAns" },
    { MOTE_MAC_PING_SLOT_INFO_REQ,      "PingSlotInfoReq" },
    { MOTE_MAC_PING_SLOT_FREQ_ANS,      "PingSlotFreqAns" },
    { MOTE_MAC_BEACON_TIMING_REQ,       "BeaconTimingReq" },
    { MOTE_MAC_BEACON_FREQ_ANS,         "BeaconFreqAns" },
};

const lw_maccmd_str_t lw_server_maccmd_str[] = {
    { SRV_MAC_LINK_CHECK_ANS,           "LinkCheckAns" },
    { SRV_MAC_LINK_ADR_REQ,             "LinkADRReq" },
    { SRV_MAC_DUTY_CYCLE_REQ,           "DutyCycleReq" },
    { SRV_MAC_RX_PARAM_SETUP_REQ,       "RXParamSetupReq" },
    { SRV_MAC_DEV_STATUS_REQ,           "DevStatusReq" },
    { SRV_MAC_NEW_CHANNEL_REQ,          "NewChannelReq" },
    { SRV_MAC_RX_TIMING_SETUP_REQ,      "RXTimingSetupReq" },
    { SRV_MAC_TX_PARAM_SETUP_REQ,       "TxParamSetupReq" },
    { SRV_MAC_DL_CHANNEL_REQ,           "DlChannelReq" },
    { SRV_MAC_PING_SLOT_INFO_ANS,       "PingSlotInfoAns" },
    { SRV_MAC_PING_SLOT_CHANNEL_REQ,    "PingSlotChannelReq" },
    { SRV_MAC_BEACON_TIMING_ANS,        "BeaconTimingAns" },
    { SRV_MAC_BEACON_FREQ_REQ,          "BeaconFreqReq" },
};

const char *lw_maccmd_str(uint8_t mtype, uint8_t cmd)
{
    int j;

    if( (mtype == LW_MTYPE_MSG_UP) || (mtype == LW_MTYPE_CMSG_UP) ){
        for(j=0; j<(sizeof(lw_node_maccmd_str)/sizeof(lw_maccmd_str_t)); j++){
            if( lw_node_maccmd_str[j].cmd == cmd ){
                return lw_node_maccmd_str[j].str;
            }
        }
    }else if( (mtype == LW_MTYPE_MSG_DOWN) || (mtype == LW_MTYPE_CMSG_DOWN) ){
        for(j=0; j<(sizeof(lw_server_maccmd_str)/sizeof(lw_maccmd_str_t)); j++){
            if( lw_server_maccmd_str[j].cmd == cmd ){
                return lw_server_maccmd_str[j].str;
            }
        }
    }
    return "Unknown";
}

void lw_no_pl(void)
{
    log_puts(LOG_NORMAL, "No MAC command payload");
}

void lw_unknown_pl(void)
{
    log_puts(LOG_NORMAL, "Unknown MAC command payload");
}

int lw_log_maccmd(uint8_t mac_header, uint8_t *opts, int len)
{
    lw_mhdr_t mhdr;
    uint16_t ChMask;
    uint8_t dr;
    int8_t power;
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
    int i, ret;

    ret = lw_maccmd_valid(mac_header, opts, len);
    if(ret != LW_OK){
        return ret;
    }

    mhdr.data = mac_header;
    band = lw_band;

    log_puts(LOG_NORMAL, "MACCMD: %H", opts, len);




    i=0;
    while(i<len){
        log_puts(LOG_NORMAL, "MACCMD ( %s )", lw_maccmd_str(mhdr.bits.mtype, opts[i]));
        if( (mhdr.bits.mtype == LW_MTYPE_MSG_UP) || (mhdr.bits.mtype == LW_MTYPE_CMSG_UP) ){
            switch(opts[i]){
                // Class A
            case MOTE_MAC_LINK_CHECK_REQ:
                lw_no_pl();
                i+=MOTE_MAC_LEN_LINK_CHECK_REQ;
                break;
            case MOTE_MAC_LINK_ADR_ANS:
                log_puts(LOG_NORMAL, "Status: 0x%02X", opts[i+1]);
                log_puts(LOG_NORMAL, "Channel mask %s", (opts[i+1]&0x01)?"ACK":"NACK");
                log_puts(LOG_NORMAL, "Data rate %s", (opts[i+1]&0x02)?"ACK":"NACK");
                log_puts(LOG_NORMAL, "Power %s", (opts[i+1]&0x04)?"ACK":"NACK");
                i+=MOTE_MAC_LEN_LINK_ADR_ANS;
                break;
            case MOTE_MAC_DUTY_CYCLE_ANS:
                i+=MOTE_MAC_LEN_DUTY_CYCLE_ANS;
                lw_no_pl();
                break;
            case MOTE_MAC_RX_PARAM_SETUP_ANS:
                log_puts(LOG_NORMAL, "Status: 0x%02X", opts[i+1]);
                log_puts(LOG_NORMAL, "Channel %s", (opts[i+1]&0x01)?"ACK":"NACK");
                log_puts(LOG_NORMAL, "RXWIN2 %s", (opts[i+1]&0x02)?"ACK":"NACK");
                log_puts(LOG_NORMAL, "RX1DRoffset %s", (opts[i+1]&0x04)?"ACK":"NACK");
                i+=MOTE_MAC_LEN_RX_PARAM_SETUP_ANS;
                break;
            case MOTE_MAC_DEV_STATUS_ANS:
                if(opts[i+1] == 0){
                    log_puts(LOG_NORMAL, "Battery: %d (External Powered)", opts[i+1]);
                }else if(opts[i+1] == 255){
                    log_puts(LOG_NORMAL, "Battery: %d (Unknown)", opts[i+1]);
                }else{
                    log_puts(LOG_NORMAL, "Battery: %d (%.1f%%)", opts[i+1], 100.0*opts[i+1]/255);
                }
                dev_sta_margin.data = opts[i+2];
                log_puts(LOG_NORMAL, "Margin: %d", dev_sta_margin.bits.margin);
                i+=MOTE_MAC_LEN_DEV_STATUS_ANS;
                break;
            case MOTE_MAC_NEW_CHANNEL_ANS:
                log_puts(LOG_NORMAL, "Status: 0x%02X", opts[i+1]);
                log_puts(LOG_NORMAL, "Channel %s", (opts[i+1]&0x01)?"ACK":"NACK");
                log_puts(LOG_NORMAL, "DataRate %s", (opts[i+1]&0x02)?"ACK":"NACK");
                i+=MOTE_MAC_LEN_NEW_CHANNEL_ANS;
                break;
            case MOTE_MAC_RX_TIMING_SETUP_ANS:
                lw_no_pl();
                i+=MOTE_MAC_LEN_RX_TIMING_SETUP_ANS;
                break;

            // TODO: parse these new commands
            case MOTE_MAC_TX_PARAM_SETUP_ANS:
                lw_unknown_pl();
                i += MOTE_MAC_LEN_TX_PARAM_SETUP_ANS;
                break;
            case MOTE_MAC_DL_CHANNEL_ANS:
                lw_unknown_pl();
                i += MOTE_MAC_LEN_DL_CHANNEL_ANS;
                break;

            //Class B
            case MOTE_MAC_PING_SLOT_INFO_REQ:
                i+=MOTE_MAC_LEN_PING_SLOT_INFO_REQ;
                lw_unknown_pl();
                break;
            case MOTE_MAC_PING_SLOT_FREQ_ANS:
                i+=MOTE_MAC_LEN_PING_SLOT_FREQ_ANS;
                lw_unknown_pl();
                break;
            case MOTE_MAC_BEACON_TIMING_REQ:
                i+=MOTE_MAC_LEN_BEACON_TIMING_REQ;
                lw_no_pl();
                break;
            case MOTE_MAC_BEACON_FREQ_ANS:
                i+=MOTE_MAC_LEN_BEACON_FREQ_ANS;
                lw_no_pl();
                break;
            }
        }else if( (mhdr.bits.mtype == LW_MTYPE_MSG_DOWN) || (mhdr.bits.mtype == LW_MTYPE_CMSG_DOWN) ){
            switch(opts[i]){
            // Class A
            case SRV_MAC_LINK_CHECK_ANS:
                if(opts[i+1] == 255){
                    log_puts(LOG_NORMAL, "Margin: %d (RFU)", opts[i+1]);
                }else{
                    log_puts(LOG_NORMAL, "Margin: %ddB", opts[i+1]);
                }
                log_puts(LOG_NORMAL, "GwCnt: %d", opts[i+2]);
                i+=SRV_MAC_LEN_LINK_CHECK_ANS;
                break;
            case SRV_MAC_LINK_ADR_REQ:
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
                i+=SRV_MAC_LEN_LINK_ADR_REQ;
                break;
            case SRV_MAC_DUTY_CYCLE_REQ:
                if(opts[i+1] == 255){
                    log_puts(LOG_NORMAL, "MaxDCycle: %d(Off)", opts[i+1]);
                }else if(opts[i+1]<16){
                    log_puts(LOG_NORMAL, "MaxDCycle: %d (%.2f%%)", opts[i+1], 100.0/pow(2,opts[i+1]));
                }else{
                    log_puts(LOG_NORMAL, "MaxDCycle: %d(RFU)", opts[i+1]);
                }
                i+=SRV_MAC_LEN_DUTY_CYCLE_REQ;
                break;
            case SRV_MAC_RX_PARAM_SETUP_REQ:
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
                i+=SRV_MAC_LEN_RX_PARAM_SETUP_REQ;
                break;
            case SRV_MAC_DEV_STATUS_REQ:
                i+=SRV_MAC_LEN_DEV_STATUS_REQ;
                lw_no_pl();
                break;
            case SRV_MAC_NEW_CHANNEL_REQ:
                freq = (opts[i+2]) | ((uint32_t)opts[i+3]<<8) | ((uint32_t)opts[i+4]<<16);
                freq *= 100;
                log_puts(LOG_NORMAL, "ChIndex: %d 0x%02X", opts[i+1], opts[i+1]);
                if(freq < 100000000){
                    log_puts(LOG_NORMAL, "Freq: %d (RFU <100MHz)", freq);
                }else{
                    log_puts(LOG_NORMAL, "Freq: %d", freq);
                }
                log_puts(LOG_NORMAL, "DrRange: 0x%02X (DR%d ~ DR%d)", opts[i+5], opts[i+5]&0x0F, opts[i+5]>>4);
                i+=SRV_MAC_LEN_NEW_CHANNEL_REQ;
                break;
            case SRV_MAC_RX_TIMING_SETUP_REQ:
                if((opts[i+1]&0x0F) == 0){
                    log_puts(LOG_NORMAL, "Del: %ds", (opts[i+1]&0x0F)+1);
                }else{
                    log_puts(LOG_NORMAL, "Del: %ds", opts[i+1]&0x0F);
                }
                i+=SRV_MAC_LEN_RX_TIMING_SETUP_REQ;
                break;
            case SRV_MAC_TX_PARAM_SETUP_REQ:
                lw_unknown_pl();
                i += SRV_MAC_LEN_TX_PARAM_SETUP_REQ;
                break;
            case SRV_MAC_DL_CHANNEL_REQ:
                lw_unknown_pl();
                i += SRV_MAC_LEN_DL_CHANNEL_REQ;
                break;
            case SRV_MAC_PING_SLOT_INFO_ANS:
                lw_unknown_pl();
                i += SRV_MAC_LEN_PING_SLOT_INFO_ANS;
                break;
            case SRV_MAC_PING_SLOT_CHANNEL_REQ:
                lw_unknown_pl();
                i += SRV_MAC_LEN_PING_SLOT_CHANNEL_REQ;
                break;
            case SRV_MAC_BEACON_TIMING_ANS:
                lw_unknown_pl();
                i += SRV_MAC_LEN_BEACON_TIMING_ANS;
                break;
            case SRV_MAC_BEACON_FREQ_REQ:
                lw_unknown_pl();
                i += SRV_MAC_LEN_BEACON_FREQ_REQ;
                break;
            }
        }
    }

    return LW_OK;
}

void lw_log(lw_frame_t *frame, uint8_t *msg, int len)
{
    uint8_t buf[16];

    log_puts(LOG_NORMAL, "MSG: %H", msg, len);

    if(frame->mhdr.bits.major == LW_VERSION_MAJOR_R1){
        log_puts(LOG_NORMAL, "LoRaWAN R1");
    }else{
        log_puts(LOG_NORMAL, "LoRaWAN version unknown");
    }

    log_puts(LOG_NORMAL, "%s", lw_mtype_str[frame->mhdr.bits.mtype]);

    log_puts(LOG_NORMAL, "MIC is OK [ %H]", frame->mic.buf, 4);

    lw_cpy(buf, frame->appeui, 8);
    log_puts(LOG_NORMAL, "APPEUI: %h", buf, 8);
    lw_cpy(buf, frame->deveui, 8);
    log_puts(LOG_NORMAL, "DEVEUI: %h", buf, 8);

    switch(frame->mhdr.bits.mtype){
    case LW_MTYPE_JOIN_REQUEST:
        log_puts(LOG_NORMAL, "DEVNONCE: 0x%04X", frame->pl.jr.devnonce.data);
        break;
    case LW_MTYPE_JOIN_ACCEPT:
        log_puts(LOG_NORMAL, "APPNONCE: 0x%06X", frame->pl.ja.appnonce.data);
        if(frame->node != NULL){
            log_puts(LOG_NORMAL, "DEVNONCE: 0x%04X", frame->node->devnonce.data);
        }
        log_puts(LOG_NORMAL, "NETID: 0x%06X", frame->pl.ja.netid.data);
        log_puts(LOG_NORMAL, "DEVADDR: %08X", frame->pl.ja.devaddr.data);
        log_puts(LOG_NORMAL, "RX2DataRate: %d", frame->pl.ja.dlsettings.bits.rx2dr);
        log_puts(LOG_NORMAL, "RX1DRoffset: %d", frame->pl.ja.dlsettings.bits.rx1droft);
        if(frame->pl.ja.cflist_len > 0){
            log_puts(LOG_NORMAL, "CFList: %H", frame->pl.ja.cflist, frame->pl.ja.cflist_len);
        }
        log_puts(LOG_NORMAL, "NWKSKEY: %H", frame->pl.ja.nwkskey, 16);
        log_puts(LOG_NORMAL, "APPSKEY: %H", frame->pl.ja.appskey, 16);
        break;
    case LW_MTYPE_MSG_UP:
    case LW_MTYPE_MSG_DOWN:
    case LW_MTYPE_CMSG_UP:
    case LW_MTYPE_CMSG_DOWN:
        log_puts(LOG_NORMAL, "DEVADDR: %08X", frame->pl.mac.devaddr.data);
        log_puts(LOG_NORMAL, "ADR: %d, ADRACKREQ: %d, ACK %d", \
                frame->pl.mac.fctrl.ul.adr, frame->pl.mac.fctrl.ul.adrackreq, frame->pl.mac.fctrl.ul.ack);
        if( (frame->mhdr.bits.mtype == LW_MTYPE_MSG_UP) && (frame->mhdr.bits.mtype == LW_MTYPE_CMSG_UP) ){
            if(frame->pl.mac.fctrl.ul.classb){
                log_puts(LOG_NORMAL, "Class B");
            }
        }else{
            if(frame->pl.mac.fctrl.dl.fpending){
                log_puts(LOG_NORMAL, "FPENDING is on");
            }
        }
        log_puts(LOG_NORMAL, "FCNT: %u [0x%08X]", frame->pl.mac.fcnt, frame->pl.mac.fcnt);

        if( (frame->pl.mac.flen > 0) && (frame->pl.mac.fport > 0) ){
            log_puts(LOG_NORMAL, "PORT: %d", frame->pl.mac.fport);
            log_puts(LOG_NORMAL, "DATA: %H", frame->pl.mac.fpl, frame->pl.mac.flen);
        }else if( (frame->pl.mac.flen > 0) && (frame->pl.mac.fport == 0) ){
            log_puts(LOG_NORMAL, "Port 0 MACCMD");
            if( LW_OK != lw_log_maccmd(frame->mhdr.data, frame->pl.mac.fpl, frame->pl.mac.flen) ){
                log_puts(LOG_ERROR, "MACCMD INVALID: %H", frame->pl.mac.fpl, frame->pl.mac.flen);
            }
        }else{
            log_puts(LOG_NORMAL, "No Port and FRMPayload in message");
        }

        if(frame->pl.mac.fctrl.ul.foptslen > 0){
            log_puts(LOG_NORMAL, "FOPTS MACCMD");
            lw_log_maccmd(frame->mhdr.data, frame->pl.mac.fopts, frame->pl.mac.fctrl.ul.foptslen);
        }
        break;
    case LW_MTYPE_RFU:

        break;
    case LW_MTYPE_PROPRIETARY:

        break;
    }

    //log_puts(LOG_NORMAL, "DMSG: %H", frame->buf, frame->len);
}

void lw_log_all_node()
{
    lw_node_t *cur = lw_node;
    log_line();
    for(; cur != NULL; cur = cur->next){
        log_puts(LOG_NORMAL, "MODE: %s", cur->mode == ABP?"ABP":"OTAA");
        log_puts(LOG_NORMAL, "JOINED: %s", cur->joined?"YES":"NO");
        log_puts(LOG_NORMAL, "DEVEUI: %H", cur->deveui, 8);
        log_puts(LOG_NORMAL, "APPEUI: %H", cur->appeui, 8);
        log_puts(LOG_NORMAL, "APPKEY: %H", cur->appkey, 16);
        log_puts(LOG_NORMAL, "APPSKEY: %H", cur->appskey, 16);
        log_puts(LOG_NORMAL, "NWKSKEY: %H", cur->nwkskey, 16);
        log_puts(LOG_NORMAL, "DEVADDR: %08X", cur->devaddr.data);
        log_puts(LOG_NORMAL, "ULSUM: %d", cur->ufsum);
        log_puts(LOG_NORMAL, "ULLOST: %d", cur->uflost);
        log_puts(LOG_NORMAL, "ULCNT: %d", cur->ufcnt);
        log_puts(LOG_NORMAL, "DLCNT: %d", cur->dfcnt);
    }
}

/* Utilities */
uint8_t lw_get_sf(uint8_t sf)
{
    int i;
    for(i=7; i<=12; i++){
        if(sf == (1<<(i-6))){
            sf = i;
            break;
        }
    }
    return sf;
}

uint16_t lw_get_bw(uint8_t bw)
{
    uint16_t bwreal = bw;
    switch (bw) {
    case BW_125KHZ: bwreal = 125; break;
    case BW_250KHZ: bwreal = 250; break;
    case BW_500KHZ: bwreal = 500; break;
    }
    return bwreal;
}

void lw_log_rxpkt(lw_rxpkt_t *rxpkt)
{
    if(rxpkt->status != STAT_CRC_OK){
        return;
    }

    log_puts(LOG_NORMAL, "\nRX: %H", rxpkt->payload, rxpkt->size);

    if(rxpkt->modulation == MOD_LORA){
        log_puts(LOG_NORMAL, "LORA,%08X(%u),%d,%d,SF%dBW%d,4/%d,%.1f,%.1f,%.1f,%.1f",
                        rxpkt->count_us,
                        rxpkt->count_us,
                        rxpkt->if_chain,
                        rxpkt->freq_hz,
                        lw_get_sf(rxpkt->datarate),
                        lw_get_bw(rxpkt->bandwidth),
                        rxpkt->coderate+4,
                        rxpkt->rssi,
                        rxpkt->snr,
                        rxpkt->snr_max,
                        rxpkt->snr_min
                 );
    }else if(rxpkt->modulation == MOD_FSK){
        log_puts(LOG_NORMAL, "FSK,%08X(%u),%d,%d,%d,%d,%.1f",
                        rxpkt->count_us,
                        rxpkt->count_us,
                        rxpkt->if_chain,
                        rxpkt->freq_hz,
                        rxpkt->datarate,
                        rxpkt->bandwidth,
                        rxpkt->rssi
                 );
    }
}

void lw_log_txpkt(lw_txpkt_t *txpkt)
{
    log_puts(LOG_NORMAL, "\nTX: %H", txpkt->payload, txpkt->size);

    if(txpkt->modulation == MOD_LORA){
        log_puts(LOG_NORMAL, "LORA,%d,%08X(%u),%d,%d,SF%dBW%d,4/%d,%d,%d,%d,%d,%d",
                        txpkt->tx_mode,
                        txpkt->count_us,
                        txpkt->count_us,
                        txpkt->rf_chain,
                        txpkt->freq_hz,
                        lw_get_sf(txpkt->datarate),
                        lw_get_bw(txpkt->bandwidth),
                        txpkt->coderate+4,
                        txpkt->rf_power,
                        txpkt->preamble,
                        txpkt->invert_pol,
                        txpkt->no_header,
                        txpkt->no_crc
                 );
    }else if(txpkt->modulation == MOD_FSK){
        log_puts(LOG_NORMAL, "FSK,%d,%08X(%u),%d,%d,%d,%d,%d,%d,%d,%d",
                        txpkt->tx_mode,
                        txpkt->count_us,
                        txpkt->count_us,
                        txpkt->rf_chain,
                        txpkt->freq_hz,
                        txpkt->rf_power,
                        txpkt->preamble,
                        txpkt->datarate,
                        txpkt->f_dev,
                        txpkt->no_header,
                        txpkt->no_crc
                 );
    }
}
