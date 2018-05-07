#include "lw-log.h"
#include "lw.h"
#include "log.h"
#include "math.h"

#include <string.h>


extern lw_node_t *lw_node;

extern const lw_region_t *lw_region;
extern const int8_t lw_pow_tab[16];

extern const int8_t lw_max_eirp_tab[16];

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

const char *lw_mtype_str_abbr[] = {
    "JR ->",
    "JA <-",
    "UU ->",
    "UD <-",
    "CU ->",
    "CD <-",
    "UK",
    "PM",
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

void lw_unknown_pl(void)
{
    log_puts(LOG_NORMAL, "Unknown MAC command payload");
}

int lw_log_maccmd(uint8_t mac_header, lw_maccmd_type_t type, uint8_t *opts, int len)
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
    int i, ret;
    char strbuf[512];

    ret = lw_maccmd_valid(mac_header, opts, len);
    if(ret != LW_OK){
        return ret;
    }

    mhdr.data = mac_header;

    log_puts(LOG_NORMAL, "MACCMD: (%s) %h", type==LW_MACCMD_FOPTS?"FOPTS":"PORT0", opts, len);

    i=0;
    while(i<len){
        strbuf[0] = '\0';
        //log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )", opts[i], lw_maccmd_str(mhdr.bits.mtype, opts[i]));
        if( (mhdr.bits.mtype == LW_MTYPE_MSG_UP) || (mhdr.bits.mtype == LW_MTYPE_CMSG_UP) ){
            switch(opts[i]){
                // Class A
            case MOTE_MAC_LINK_CHECK_REQ:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )", opts[i], lw_maccmd_str(mhdr.bits.mtype, opts[i]));
                i+=MOTE_MAC_LEN_LINK_CHECK_REQ;
                break;
            case MOTE_MAC_LINK_ADR_ANS:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "Status: 0x%02X"           ", "
                                     "Channel mask: %s"         ", "
                                     "Data rate: %s"            ", "
                                     "Power: %s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     opts[i+1],
                                     (opts[i+1]&0x01)?"ACK":"NACK",
                                     (opts[i+1]&0x02)?"ACK":"NACK",
                                     (opts[i+1]&0x04)?"ACK":"NACK");
                i+=MOTE_MAC_LEN_LINK_ADR_ANS;
                break;
            case MOTE_MAC_DUTY_CYCLE_ANS:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )", opts[i], lw_maccmd_str(mhdr.bits.mtype, opts[i]));
                i+=MOTE_MAC_LEN_DUTY_CYCLE_ANS;
                break;
            case MOTE_MAC_RX_PARAM_SETUP_ANS:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "Status: 0x%02X"           ", "
                                     "Channel: %s"              ", "
                                     "RXWIN2: %s"               ", "
                                     "RX1DRoffset: %s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     opts[i+1],
                                     (opts[i+1]&0x01)?"ACK":"NACK",
                                     (opts[i+1]&0x02)?"ACK":"NACK",
                                     (opts[i+1]&0x04)?"ACK":"NACK");
                i+=MOTE_MAC_LEN_RX_PARAM_SETUP_ANS;
                break;
            case MOTE_MAC_DEV_STATUS_ANS:
                if(opts[i+1] == 0){
                    sprintf(strbuf, "%d (External Powered)", opts[i+1]);
                }else if(opts[i+1] == 255){
                    sprintf(strbuf, "%d (Unknown)", opts[i+1]);
                }else{
                    sprintf(strbuf, "%d (%.1f%%)", opts[i+1], 100.0*opts[i+1]/255);
                }
                dev_sta_margin.data = opts[i+2];

                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "Battery: %s"              ", "
                                     "Margin: %d",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf,
                                     dev_sta_margin.bits.margin);
                i+=MOTE_MAC_LEN_DEV_STATUS_ANS;
                break;
            case MOTE_MAC_NEW_CHANNEL_ANS:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "Status: 0x%02X"           ", "
                                     "Channel mask: %s"         ", "
                                     "Data rate: %s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     opts[i+1],
                                     (opts[i+1]&0x01)?"ACK":"NACK",
                                     (opts[i+1]&0x02)?"ACK":"NACK");
                i+=MOTE_MAC_LEN_NEW_CHANNEL_ANS;
                break;
            case MOTE_MAC_RX_TIMING_SETUP_ANS:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )", opts[i], lw_maccmd_str(mhdr.bits.mtype, opts[i]));
                i+=MOTE_MAC_LEN_RX_TIMING_SETUP_ANS;
                break;

            case MOTE_MAC_TX_PARAM_SETUP_ANS:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )", opts[i], lw_maccmd_str(mhdr.bits.mtype, opts[i]));
                i += MOTE_MAC_LEN_TX_PARAM_SETUP_ANS;
                break;
            case MOTE_MAC_DL_CHANNEL_ANS:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "Channel Frequency: %s"    ", "
                                     "Uplink Frequency: %s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     (opts[i+1]&0x01)?"ACK":"NACK",
                                     (opts[i+1]&0x02)?"ACK":"NACK");
                i += MOTE_MAC_LEN_DL_CHANNEL_ANS;
                break;

            //Class B
            case MOTE_MAC_PING_SLOT_INFO_REQ:
#ifdef LORAWAN_V11_CLASSB
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "Periodicity: %ds",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     ( 1<<(opts[i+1]&0x07) ));
#else
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "Periodicity: %ds"         ", "
                                     "DataRate: %d",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     ( 1<<((opts[i+1]>>4)&0x07) ),
                                     (opts[i+1]&0x0F));
#endif
                i+=MOTE_MAC_LEN_PING_SLOT_INFO_REQ;
                break;
            case MOTE_MAC_PING_SLOT_FREQ_ANS:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "Channel Frequency: %s"    ", "
                                     "Data Rate Range: %s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     (opts[i+1]&0x01)!=0?"ACK":"NACK",
                                     (opts[i+1]&0x02)!=0?"ACK":"NACK");
                i+=MOTE_MAC_LEN_PING_SLOT_FREQ_ANS;
                break;
            case MOTE_MAC_BEACON_TIMING_REQ:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )", opts[i], lw_maccmd_str(mhdr.bits.mtype, opts[i]));
                i+=MOTE_MAC_LEN_BEACON_TIMING_REQ;
                break;
            case MOTE_MAC_BEACON_FREQ_ANS:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )", opts[i], lw_maccmd_str(mhdr.bits.mtype, opts[i]));
                i+=MOTE_MAC_LEN_BEACON_FREQ_ANS;
                break;
            }
        }else if( (mhdr.bits.mtype == LW_MTYPE_MSG_DOWN) || (mhdr.bits.mtype == LW_MTYPE_CMSG_DOWN) ){
            switch(opts[i]){
            // Class A
            case SRV_MAC_LINK_CHECK_ANS:
                if(opts[i+1] == 255){
                    sprintf(strbuf, "%d (RFU)", opts[i+1]);
                }else{
                    sprintf(strbuf, "%ddB", opts[i+1]);
                }
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "Margin: %s"               ", "
                                     "GwCnt: %d",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf,
                                      opts[i+2]);
                i+=SRV_MAC_LEN_LINK_CHECK_ANS;
                break;
            case SRV_MAC_LINK_ADR_REQ:
                dr = lw_region->dr_tab[opts[i+1]>>4];
                power = lw_pow_tab[opts[i+1]&0x0F];
                chmaskcntl = lw_region->chmaskcntl_tab[(opts[i+4]>>4)&0x07];
                ChMask = opts[i+2] + (((uint16_t)opts[i+3])<<8);

                if(power == LW_POW_RFU){
                    sprintf(strbuf+strlen(strbuf), "TXPower: %d (RFU)", opts[i+1]&0x0F);
                }else{
                    sprintf(strbuf+strlen(strbuf), "TXPower: %d (%ddBm)", opts[i+1]&0x0F, power);
                }
                sprintf(strbuf+strlen(strbuf), ", ");

                if(dr == LW_DR_RFU){
                    sprintf(strbuf+strlen(strbuf), "DataRate: DR%d (RFU)", opts[i+1]>>4);
                }else if( (dr&0x0F) == FSK){
                    sprintf(strbuf+strlen(strbuf), "DataRate: DR%d (FSK)", opts[i+1]>>4);
                }else{
                    sprintf(strbuf+strlen(strbuf), "DataRate: DR%d (SF%d/BW%dKHz)", opts[i+1]>>4, dr&0x0F, (int)(125*pow(2,dr>>4)));
                }
                sprintf(strbuf+strlen(strbuf), ", ");

                sprintf(strbuf+strlen(strbuf), "ChMask: 0x%04X", ChMask);
                sprintf(strbuf+strlen(strbuf), ", ");

                sprintf(strbuf+strlen(strbuf), "NbRep: %d", opts[i+4]&0x0F);
                sprintf(strbuf+strlen(strbuf), ", ");
                switch(chmaskcntl){
                case LW_CMC_RFU:
                    sprintf(strbuf+strlen(strbuf), "ChMaskCntl: %d (RFU)", (opts[i+4]>>4)&0x07);
                    break;
                case LW_CMC_ALL_ON:
                    sprintf(strbuf+strlen(strbuf), "ChMaskCntl: %d (EU868 All on)", (opts[i+4]>>4)&0x07);
                    break;
                case LW_CMC_ALL_125KHZ_ON:
                    sprintf(strbuf+strlen(strbuf), "ChMaskCntl: %d, All 125KHz channels on, ChMask applies to 64 ~ 71", (opts[i+4]>>4)&0x07);
                    break;
                case LW_CMC_ALL_125KHZ_OFF:
                    sprintf(strbuf+strlen(strbuf), "ChMaskCntl: %d, All 125KHz channels off, ChMask applies to 64 ~ 71", (opts[i+4]>>4)&0x07);
                    break;
                default:
                    sprintf(strbuf+strlen(strbuf), "ChMaskCntl: %d, ChMask applies to %d ~ %d", (opts[i+4]>>4)&0x07, chmaskcntl*16, (chmaskcntl+1)*16-1);
                    break;
                }

                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "%s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf);
                i+=SRV_MAC_LEN_LINK_ADR_REQ;
                break;
            case SRV_MAC_DUTY_CYCLE_REQ:
                if(opts[i+1] == 255){
                    sprintf(strbuf+strlen(strbuf), "MaxDCycle: %d(Off)", opts[i+1]);
                }else if(opts[i+1]<16){
                    sprintf(strbuf+strlen(strbuf), "MaxDCycle: %d (%.2f%%)", opts[i+1], 100.0/pow(2,opts[i+1]));
                }else{
                    sprintf(strbuf+strlen(strbuf), "MaxDCycle: %d(RFU)", opts[i+1]);
                }
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "%s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf);
                i+=SRV_MAC_LEN_DUTY_CYCLE_REQ;
                break;
            case SRV_MAC_RX_PARAM_SETUP_REQ:
                rx1drofst = (opts[i+1]>>4) & 0x07;
                rx2dr = lw_region->dr_tab[opts[i+1] & 0x0F];
                freq = (opts[i+2]) | ((uint32_t)opts[i+3]<<8) | ((uint32_t)opts[i+4]<<16);
                freq *= 100;

                sprintf(strbuf+strlen(strbuf), "RX1DROffset: %d", rx1drofst);
                sprintf(strbuf+strlen(strbuf), ", ");

                if(rx2dr == LW_DR_RFU){
                    sprintf(strbuf+strlen(strbuf), "RX2DataRate: DR%d (RFU)", opts[i+1] & 0x0F);
                }else if( (rx2dr&0x0F) == FSK){
                    sprintf(strbuf+strlen(strbuf), "RX2DataRate: DR%d (FSK)", opts[i+1] & 0x0F);
                }else{
                    sprintf(strbuf+strlen(strbuf), "RX2DataRate: DR%d (SF%d/BW%dKHz)", opts[i+1] & 0x0F, rx2dr&0x0F, (int)(125*pow(2,rx2dr>>4)));
                }
                sprintf(strbuf+strlen(strbuf), ", ");

                if( (freq < 100000000) && (freq != 0) ){
                    sprintf(strbuf+strlen(strbuf), "Freq: %d (RFU <100MHz)", freq);
                }else{
                    sprintf(strbuf+strlen(strbuf), "Freq: %d", freq);
                }
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "%s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf);
                i+=SRV_MAC_LEN_RX_PARAM_SETUP_REQ;
                break;
            case SRV_MAC_DEV_STATUS_REQ:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]));
                i+=SRV_MAC_LEN_DEV_STATUS_REQ;
                break;
            case SRV_MAC_NEW_CHANNEL_REQ:
                freq = (opts[i+2]) | ((uint32_t)opts[i+3]<<8) | ((uint32_t)opts[i+4]<<16);
                freq *= 100;

                sprintf(strbuf+strlen(strbuf), "ChIndex: %d 0x%02X", opts[i+1], opts[i+1]);
                sprintf(strbuf+strlen(strbuf), ", ");

                if( (freq < 100000000) && (freq != 0) ){
                    sprintf(strbuf+strlen(strbuf), "Freq: %d (RFU <100MHz)", freq);
                }else{
                    sprintf(strbuf+strlen(strbuf), "Freq: %d", freq);
                }
                sprintf(strbuf+strlen(strbuf), ", ");

                sprintf(strbuf+strlen(strbuf), "DrRange: 0x%02X (DR%d ~ DR%d)", opts[i+5], opts[i+5]&0x0F, opts[i+5]>>4);

                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "%s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf);
                i+=SRV_MAC_LEN_NEW_CHANNEL_REQ;
                break;
            case SRV_MAC_RX_TIMING_SETUP_REQ:
                if((opts[i+1]&0x0F) == 0){
                    sprintf(strbuf+strlen(strbuf), "Del: %ds", (opts[i+1]&0x0F)+1);
                }else{
                    sprintf(strbuf+strlen(strbuf), "Del: %ds", opts[i+1]&0x0F);
                }

                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "%s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf);

                i+=SRV_MAC_LEN_RX_TIMING_SETUP_REQ;
                break;
            case SRV_MAC_TX_PARAM_SETUP_REQ:
                sprintf(strbuf+strlen(strbuf), "MaxEIRP: %ddBm", lw_max_eirp_tab[(opts[i+1] & 0x0F)]);
                sprintf(strbuf+strlen(strbuf), ", ");
                sprintf(strbuf+strlen(strbuf), "UplinkDwellTime: %d", (opts[i+1]&0x10)?1:0);
                sprintf(strbuf+strlen(strbuf), ", ");
                sprintf(strbuf+strlen(strbuf), "DownlinkDwellTime: %d", (opts[i+1]&0x10)?1:0);

                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "%s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf);

                i += SRV_MAC_LEN_TX_PARAM_SETUP_REQ;
                break;
            case SRV_MAC_DL_CHANNEL_REQ:
                freq = (opts[i+2]) | ((uint32_t)opts[i+3]<<8) | ((uint32_t)opts[i+4]<<16);
                freq *= 100;

                sprintf(strbuf+strlen(strbuf), "ChIndex: %d", opts[i+1]);
                sprintf(strbuf+strlen(strbuf), ", ");

                if( (freq < 100000000) && (freq != 0) ){
                    sprintf(strbuf+strlen(strbuf), "Freq: %d (RFU <100MHz)", freq);
                }else{
                    sprintf(strbuf+strlen(strbuf), "Freq: %d", freq);
                }

                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "%s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf);

                i += SRV_MAC_LEN_DL_CHANNEL_REQ;
                break;

            case SRV_MAC_PING_SLOT_INFO_ANS:
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]));
                i += SRV_MAC_LEN_PING_SLOT_INFO_ANS;
                break;
            case SRV_MAC_PING_SLOT_CHANNEL_REQ:
                freq = (opts[i+1]) | ((uint32_t)opts[i+2]<<8) | ((uint32_t)opts[i+3]<<16);
                freq *= 100;
                if( (freq < 100000000) && (freq != 0) ){
                    sprintf(strbuf+strlen(strbuf), "Freq: %d (RFU <100MHz)", freq);
                }else{
                    sprintf(strbuf+strlen(strbuf), "Freq: %d", freq);
                }
                sprintf(strbuf+strlen(strbuf), ", ");
#ifdef LORAWAN_V11_CLASSB
                sprintf(strbuf+strlen(strbuf), "Data Rate: DR%d", opts[i+4]&0x0F);
#else
                sprintf(strbuf+strlen(strbuf), "Data Rate: DR%d ~ DR%d", opts[i+4]&0x0F, (opts[i+4]>>4)&0x0F);
#endif
                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "%s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf);

                i += SRV_MAC_LEN_PING_SLOT_CHANNEL_REQ;
                break;
            case SRV_MAC_BEACON_TIMING_ANS:
            {
                uint32_t delay = (opts[i+1]) | ((uint16_t)opts[i+2]<<8);
                uint8_t channel = opts[i+3];
                if(channel == 0){
                    sprintf(strbuf+strlen(strbuf), "Beacon channel fixed");
                }else{
                    sprintf(strbuf+strlen(strbuf),"Beacon channel %d", channel);
                }
                sprintf(strbuf+strlen(strbuf), ", ");

                sprintf(strbuf+strlen(strbuf),"RTime: %d ~ %dms (TX end to beacon start)", 30*delay, 30*(delay+1));

                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "%s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf);

                i += SRV_MAC_LEN_BEACON_TIMING_ANS;
            }
                break;
            case SRV_MAC_BEACON_FREQ_REQ:
                freq = (opts[i+1]) | ((uint32_t)opts[i+2]<<8) | ((uint32_t)opts[i+3]<<16);
                freq *= 100;
                if( (freq < 100000000) && (freq != 0) ){
                    sprintf(strbuf+strlen(strbuf), "Freq: %d (RFU <100MHz)", freq);
                }else{
                    sprintf(strbuf+strlen(strbuf), "Freq: %d", freq);
                }

                log_puts(LOG_NORMAL, "MACCMD: %02X ( %s )"      ", "
                                     "%s",
                                     opts[i],
                                     lw_maccmd_str(mhdr.bits.mtype, opts[i]),
                                     strbuf);
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
    char *fctrlbitstr;

    log_puts(LOG_NORMAL, "MSG: (%2s) %h", lw_mtype_str_abbr[frame->mhdr.bits.mtype], msg, len);

#if 0
    if(frame->mhdr.bits.major == LW_VERSION_MAJOR_R1){
        log_puts(LOG_NORMAL, "LoRaWAN R1");
    }else{
        log_puts(LOG_NORMAL, "LoRaWAN version unknown");
    }

    log_puts(LOG_NORMAL, "%s", lw_mtype_str[frame->mhdr.bits.mtype]);
#endif
    lw_cpy(buf, frame->appeui, 8);
    lw_cpy(buf+8, frame->deveui, 8);


    switch(frame->mhdr.bits.mtype){
    case LW_MTYPE_JOIN_REQUEST:
        log_puts(LOG_NORMAL, "APPEUI: %h, DEVEUI: %h", buf, 8, buf+8, 8);
        log_puts(LOG_NORMAL, "DEVNONCE: 0x%04X", frame->pl.jr.devnonce.data);
        break;
    case LW_MTYPE_JOIN_ACCEPT:
        log_puts(LOG_NORMAL, "APPEUI: %h, DEVEUI: %h", buf, 8, buf+8, 8);
        log_puts(LOG_NORMAL, "APPNONCE: 0x%06X", frame->pl.ja.appnonce.data);
        if(frame->node != NULL){
            log_puts(LOG_NORMAL, "DEVNONCE: 0x%04X", frame->node->devnonce.data);
        }
        log_puts(LOG_NORMAL, "RX2DataRate: %d", frame->pl.ja.dlsettings.bits.rx2dr);
        log_puts(LOG_NORMAL, "RX1DRoffset: %d", frame->pl.ja.dlsettings.bits.rx1droft);
        log_puts(LOG_NORMAL, "NETID: 0x%06X", frame->pl.ja.netid.data);
        log_puts(LOG_NORMAL, "DEVADDR: %08X", frame->pl.ja.devaddr.data);
        log_puts(LOG_NORMAL, "NWKSKEY: %h", frame->pl.ja.nwkskey, 16);
        log_puts(LOG_NORMAL, "APPSKEY: %h", frame->pl.ja.appskey, 16);
        if(frame->pl.ja.cflist_len > 0){
            int i, freq;
            log_puts(LOG_NORMAL, "CFList: %h", frame->pl.ja.cflist, frame->pl.ja.cflist_len);
            uint8_t *buf = frame->pl.ja.cflist;
            i = 0;
            while((i+3)<=frame->pl.ja.cflist_len){
                freq = (buf[i+0]) | ((uint32_t)buf[i+1]<<8) | ((uint32_t)buf[i+2]<<16);
                freq *= 100;
                log_puts(LOG_NORMAL, "CHx: %d", freq);
                i += 3;
            }
        }
        break;
    case LW_MTYPE_MSG_UP:
    case LW_MTYPE_MSG_DOWN:
    case LW_MTYPE_CMSG_UP:
    case LW_MTYPE_CMSG_DOWN:
        fctrlbitstr = "";
        if( (frame->mhdr.bits.mtype == LW_MTYPE_MSG_UP) || (frame->mhdr.bits.mtype == LW_MTYPE_CMSG_UP) ){
            if(frame->pl.mac.fctrl.ul.classb){
                fctrlbitstr = ", CLASSB";
            }
        }else{
            if(frame->pl.mac.fctrl.dl.fpending){
                fctrlbitstr = ", FPENDING";
            }
        }

        log_puts(LOG_NORMAL, "APPEUI: %h, DEVEUI: %h, DEVADDR: %08X, ADR: %d, ADRACKREQ: %d, ACK :%d, FCNT: %u [0x%08X], MIC: %h%s",
            buf, 8,
            buf+8, 8,
            frame->pl.mac.devaddr.data,
            frame->pl.mac.fctrl.ul.adr, frame->pl.mac.fctrl.ul.adrackreq, frame->pl.mac.fctrl.ul.ack,
            frame->pl.mac.fcnt, frame->pl.mac.fcnt,
            frame->mic.buf, 4,
            fctrlbitstr);

        if( (frame->pl.mac.flen > 0) && (frame->pl.mac.fport > 0) ){
            log_puts(LOG_NORMAL, "PORT: %d, LEN: %d, DATA: %h",
                     frame->pl.mac.fport,
                     frame->pl.mac.flen,
                     frame->pl.mac.fpl, frame->pl.mac.flen);
        }else if( (frame->pl.mac.flen > 0) && (frame->pl.mac.fport == 0) ){
            if( LW_OK != lw_log_maccmd(frame->mhdr.data, LW_MACCMD_PORT0, frame->pl.mac.fpl, frame->pl.mac.flen) ){
                log_puts(LOG_ERROR, "MACCMD INVALID: %h (Port 0)", frame->pl.mac.fpl, frame->pl.mac.flen);
            }
        }else{
            log_puts(LOG_NORMAL, "No Port and FRMPayload");
        }

        if(frame->pl.mac.fctrl.ul.foptslen > 0){
            if( LW_OK != lw_log_maccmd(frame->mhdr.data, LW_MACCMD_FOPTS, frame->pl.mac.fopts, frame->pl.mac.fctrl.ul.foptslen) ){
                log_puts(LOG_ERROR, "MACCMD INVALID: %h (FOpts)", frame->pl.mac.fopts, frame->pl.mac.fctrl.ul.foptslen);
            }
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
    log_puts(LOG_INFO, "Node List:");
    log_puts(LOG_NORMAL, "mode,joined,appeui,deveui,devaddr,appkey,nwkskey,appskey,ulsum,ullost,ufcnt,dfcnt");
    for(; cur != NULL; cur = cur->next){
        log_puts(LOG_NORMAL, "%s,%s,%h,%h,%08X,%h,%h,%h,%u,%u,%u,%u",
                             cur->mode == ABP?"ABP":"OTAA",
                             cur->joined?"YES":"NO",
                             cur->appeui, 8,
                             cur->deveui, 8,
                             cur->devaddr.data,
                             cur->appkey, 16,
                             cur->nwkskey, 16,
                             cur->appskey, 16,
                             cur->ufsum,
                             cur->uflost,
                             cur->ufcnt,
                             cur->dfcnt);
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
