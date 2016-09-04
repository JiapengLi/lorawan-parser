#ifndef __LW_MACRO_H
#define __LW_MACRO_H

#define LW_VERSION_MAJOR_R1                     (0x00)

enum{
    // Error code
    LW_OK                   = 0,
    LW_ERR_CMD_UNKNOWN      = -1,
    LW_ERR_PL_LEN           = -2,
    LW_ERR_MIC              = -3,
    LW_ERR_DECRYPT          = -4,
    LW_ERR_MACCMD           = -5,
    LW_ERR_MACCMD_LEN       = -6,
    LW_ERR_FOPTS_PORT0      = -7,
    LW_ERR_JOINR_LEN        = -8,
    LW_ERR_JOINA_LEN        = -9,
    LW_ERR_MALLOC           = -10,
    LW_ERR_NOT_AVALAIBLE    = -11,
    LW_ERR_BAND             = -12,
    LW_ERR_PARA             = -13,
    LW_ERR_NODE_USED_UP     = -14,
    LW_ERR_UNKOWN_FRAME     = -15,
    LW_ERR_TX_BUF_NOT_EMPTY = -16,
    LW_ERR_UNKOWN_DEVEUI    = -17,
    LW_ERR_NO_HEAP          = -18,
    LW_ERR_UNKOWN_DATA_RATE = -19,
    LW_ERR_FRAME_TOO_SHORT  = -20,
};

typedef enum{
    LW_MTYPE_JOIN_REQUEST   = 0x00,
    LW_MTYPE_JOIN_ACCEPT    = 0x01,
    LW_MTYPE_MSG_UP         = 0x02,
    LW_MTYPE_MSG_DOWN       = 0x03,
    LW_MTYPE_CMSG_UP        = 0x04,
    LW_MTYPE_CMSG_DOWN      = 0x05,
    LW_MTYPE_RFU            = 0x06,
    LW_MTYPE_PROPRIETARY    = 0x07
}lw_mtype_t;

enum{
    LW_MHDR                 = 0x00,
};

enum {
    // Data frame format
    //LW_OFF_DAT_HDR        = 0,
    LW_DATA_OFF_DEVADDR     = 1,
    LW_DATA_OFF_FCTRL       = 5,
    LW_DATA_OFF_FCNT        = 6,
    LW_DATA_OFF_FOPTS       = 8,
};

enum {
    // Join Request frame format (offset)
    //LW_OFF_JR_HDR         = 0,
    LW_JR_OFF_APPEUI        = 1,
    LW_JR_OFF_DEVEUI        = 9,
    LW_JR_OFF_DEVNONCE      = 17,
    LW_JR_OFF_MIC           = 19,
    LW_JR_LEN               = 23
};
enum {
    // Join Accept frame format (offset)
    //LW_OFF_JA_HDR         = 0,
    LW_JA_OFF_APPNONCE      = 1,
    LW_JA_OFF_NETID         = 4,
    LW_JA_OFF_DEVADDR       = 7,
    LW_JA_OFF_DLSET         = 11,
    LW_JA_OFF_RXDLY         = 12,
    LW_JA_OFF_CFLIST        = 13,
    LW_JA_LEN               = 17,
    LW_JA_LEN_EXT           = 17+16
};

// MAC uplink commands   downwlink too
enum {
    // Class A
    LW_MCMD_LCHK_REQ = 0x02, // -  link check request : -
    LW_MCMD_LADR_ANS = 0x03, // -  link ADR answer    : u1:7-3:RFU, 3/2/1: pow/DR/Ch ACK
    LW_MCMD_DCAP_ANS = 0x04, // -  duty cycle answer  : -
    LW_MCMD_DN2P_ANS = 0x05, // -  2nd DN slot status : u1:7-2:RFU  1/0:datarate/channel ack
    LW_MCMD_DEVS_ANS = 0x06, // -  device status ans  : u1:battery 0,1-254,255=?, u1:7-6:RFU,5-0:margin(-32..31)
    LW_MCMD_SNCH_ANS = 0x07, // -  set new channel    : u1: 7-2=RFU, 1/0:DR/freq ACK
    LW_MCMD_RXTS_ANS = 0x08, // -  RX timing setup    :
    // Class B
    LW_MCMD_PING_IND = 0x10, // -  pingability indic  : u1: 7=RFU, 6-4:interval, 3-0:datarate
    LW_MCMD_PING_ANS = 0x11, // -  ack ping freq      : u1: 7-1:RFU, 0:freq ok
    LW_MCMD_BCNI_REQ = 0x12, // -  next beacon start  :
};

enum {
    // Class A
    LW_MCMD_LCHK_REQ_LEN = 1, // -  link check request : -
    LW_MCMD_LADR_ANS_LEN = 2, // -  link ADR answer    : u1:7-3:RFU, 3/2/1: pow/DR/Ch ACK
    LW_MCMD_DCAP_ANS_LEN = 1, // -  duty cycle answer  : -
    LW_MCMD_DN2P_ANS_LEN = 2, // -  2nd DN slot status : u1:7-2:RFU  1/0:datarate/channel ack
    LW_MCMD_DEVS_ANS_LEN = 3, // -  device status ans  : u1:battery 0,1-254,255=?, u1:7-6:RFU,5-0:margin(-32..31)
    LW_MCMD_SNCH_ANS_LEN = 2, // -  set new channel    : u1: 7-2=RFU, 1/0:DR/freq ACK
    LW_MCMD_RXTS_ANS_LEN = 1,
    // Class B
    LW_MCMD_PING_IND_LEN = 1, // -  pingability indic  : u1: 7=RFU, 6-4:interval, 3-0:datarate
    LW_MCMD_PING_ANS_LEN = 1, // -  ack ping freq      : u1: 7-1:RFU, 0:freq ok
    LW_MCMD_BCNI_REQ_LEN = 1, // -  next beacon start  : -
};

// MAC downlink commands
enum {
    // Class A
    LW_MCMD_LCHK_ANS = 0x02, // link check answer  : u1:margin 0-254,255=unknown margin / u1:gwcnt
    LW_MCMD_LADR_REQ = 0x03, // link ADR request   : u1:DR/TXPow, u2:chmask, u1:chpage/repeat
    LW_MCMD_DCAP_REQ = 0x04, // duty cycle cap     : u1:255 dead [7-4]:RFU, [3-0]:cap 2^-k
    LW_MCMD_DN2P_REQ = 0x05, // 2nd DN window param: u1:7-4:RFU/3-0:datarate, u3:freq
    LW_MCMD_DEVS_REQ = 0x06, // device status req  : -
    LW_MCMD_SNCH_REQ = 0x07, // set new channel    : u1:chidx, u3:freq, u1:DRrange
    LW_MCMD_RXTS_REQ = 0x08, // RX timing setup    :
    // Class B
    LW_MCMD_PING_SET = 0x11, // set ping freq      : u3: freq
    LW_MCMD_BCNI_ANS = 0x12, // next beacon start  : u2: delay(in TUNIT millis), u1:channel
};

// MAC downlink commands
enum {
    // Class A
    LW_MCMD_LCHK_ANS_LEN = 3, // link check answer  : u1:margin 0-254,255=unknown margin / u1:gwcnt
    LW_MCMD_LADR_REQ_LEN = 5, // link ADR request   : u1:DR/TXPow, u2:chmask, u1:chpage/repeat
    LW_MCMD_DCAP_REQ_LEN = 2, // duty cycle cap     : u1:255 dead [7-4]:RFU, [3-0]:cap 2^-k
    LW_MCMD_DN2P_REQ_LEN = 5, // 2nd DN window param: u1:7-4:RFU/3-0:datarate, u3:freq
    LW_MCMD_DEVS_REQ_LEN = 1, // device status req  : -
    LW_MCMD_SNCH_REQ_LEN = 6, // set new channel    : u1:chidx, u3:freq, u1:DRrange
    LW_MCMD_RXTS_REQ_LEN = 2, // RX timing setup    :
    // Class B
    LW_MCMD_PING_SET_LEN = 1, // set ping freq      : u3: freq
    LW_MCMD_BCNI_ANS_LEN = 1, // next beacon start  : u2: delay(in TUNIT millis), u1:channel
};

#endif // __LW_MACRO_H
