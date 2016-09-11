# Introduction

This LoRaWAN tool is for LoRaWAN developers who need know the details of LoRaWAN protocol.

With lorawan-parser, one could see all details of LoRaWAN, like how frames are defined, how data is encrypted and decrypted etc.

## Features

- [x] Support LoRaWAN 1.0 protocol
- [x] Support both ABP and OTAA mode device
- [x] Colorful terminal outputs (Windows MiniTTY not supported)
- [X] Cross platform (Tested on Ubuntu, Lubuntu, Raspberry Pi, OpenWRT, Windows)
- [ ] Support LoRaWAN 1.0.2 protocol
- [ ] Support Semtech packet forwarder v1 and v2 protocol
- [ ] Live parse LoRaWAN motes message (To support Semtech IoT Start Kit)

## Usage

Refer to `util/test/main.c` to know the usage of lorawan API.

After compile find `lwp.exe/lwp` under `util/parser/` directory to parse the LoRaWAN frame.

```
--------------------------------------------------------------------------------
Usage: lwp [OPTIONS]
 -h, --help                     Help
 -v, --version                  Version 0.2.0

--------------------------------------------------------------------------------
 -c, --burst-parse  <file>      Parse lwp json format file
 -m, --maccmd       <hex>       Parse MAC command
 -p, --parse        [hex]       Parse packet
 -g, --pack         [hex]       Generate packet
 -f, --pktfwd       [file]      Packet forwarder mode

--------------------------------------------------------------------------------
 -B, --band         <string>    PHY band EU868/US915/EU434/AU920/CN780/CN470
 -N, --nwkskey      <hex>       NwkSKey
 -A, --appskey      <hex>       AppSKey
 -K, --appkey       <hex>       AppKey

--------------------------------------------------------------------------------
 -T, --type         <string>    Frame type (JR/JA/UU/UD/CU/CD/P)
 -D, --devaddr      <hex>       DevAddr
     --ack                      FCtrl ACK
     --aareq                    FCtrl ADRACKReq
     --adr                      FCtrl ADR
     --classb                   FCtrl CLASSB
     --fpending                 FCtrl FPENDING
 -O, --fopts        <hex>       FOpts, LoRaWAN Options
 -C                 <hex>       Frame counter (hex)
     --counter      <int>       Frame counter (int)
 -P                 <hex>       Port (hex)
     --port         <int>       Port (int)

--------------------------------------------------------------------------------
     --appeui       <hex>       AppEui
     --deveui       <hex>       DevEui
     --anonce       <hex>       AppNonce (3 byets)
     --dnonce       <hex>       DevNonce (2 byets)
     --netid        <hex>       NetId (3 byets)
     --cflist       <hex>       CFList (16 bytes)
     --rx1droft     <int>       RX1DRoffset (0~7)
     --rx2dr        <int>       RX2DataRate (0~15)
     --rxdelay      <int>       RxDelay (0~15)

--------------------------------------------------------------------------------
     --motes        <file>      Motes/Nodes JSON file
     --nodes        <file>      Same as --motes

--------------------------------------------------------------------------------
 -b, --board        <file>      Board specific TX power table and RSSI offset

--------------------------------------------------------------------------------
Default AppKey/NwkSKey/AppSKey 2B7E151628AED2A6ABF7158809CF4F3C

```

### Burst Parse LoRaWAN Frame
```
$ ./lwp -c lwp-config.json
```

To go further, user could fill their own LoRaWAN frames in a json file to parse it.

### Pack LoRaWAN frame
```
# Unconfirmed uplink
$ ./lwp --pack "00112233" -T UU --devaddr 01111111 --adr --ack --counter 1113 --port 2

# Confirmed uplink without payload
$ ./lwp --pack -T CU --devaddr 01111111 --adr --ack --aareq --counter 1113

# Unconfirmed downlink
$ ./lwp --pack "00112233" -T UD --devaddr 01111111 --adr --ack --port 2 --counter 1113

# Confirmed downlink without payload, frame pending set
$ ./lwp --pack -T CD --devaddr 01111111 --adr --ack --pending --counter 1113

# Join request
$ ./lwp --pack -T JR --deveui 0123456789ABCDEF --appeui 0000000000000001 --dnonce ABCD

# Join accept, --dnonce is used to generate NwkSKey and AppSKey
$ ./lwp --pack -T JA --devaddr 0123456 --anonce ABCDEF --netid 000008 --rx1droft 0 --rx2dr 0 --rxdelay 1 --dnonce ABCD
```

### Parse LoRaWAN frame
```
# Parser with specified keys
$ ./lwp --parse "40 11 11 11 01 A0 59 04 02 0F A0 9D 7C 61 F3 FA B7" --nwkskey 2B7E151628AED2A6ABF7158809CF4F3C --appskey 2B7E151628AED2A6ABF7158809CF4F3C --appkey 2B7E151628AED2A6ABF7158809CF4F3C

# Parse with default key
$ ./lwp --parse "40 11 11 11 01 A0 59 04 02 0F A0 9D 7C 61 F3 FA B7"
```

### Parse LoRaWAN MACCMD
```
$ lwp -T CD -m "02 30 01"
```

## Compile

### Linux

Depends on tools *libtool*, *automake*. To build:

    cd lorawan-parser
    autoreconf -i
    ./configure
    make

### Windows

#### Codeblocks
lorawan-parser supports [Codeblocks](http://www.codeblocks.org/) project. One could download Codeblocks from its official website.

#### CMake
*Not supported yet. You are welcome to submit CMake patches.*

### Raspberry Pi

    sudo apt-get install autoconf libtool
    autoreconf -i
    ./configure
    make

### Big Endian Platform

Thank @huzhifeng help test on MIPS platform

    autoreconf -i
    ./configure --enable-big-endian
    make


## Limitation

lorawan-parser only handles frames of which real frame counter is less than 0xFFFF, this is because an exact LoRaWAN frame only record low 16bits of the frame, the parser alwarys assumes the high 16bits is zero.

### Frame counter enhancement
API is updated to receive frame counter 16 most-significante bits passed from user. This makes it possible to emunate the frame counter most significante bits when a frame is known to be valid

## Contribute

Any kind of contributions are welcome, issue report, pull requests,  WIKI, suggestions...

Before you send pull request, please try to make your code keep same style as the original one.

## License
lorawan-paser and is licensed under [The MIT License](http://opensource.org/licenses/mit-license.php). Check LICENSE.txt for more information.

parson, AES, CMAC have its own licenses. Please follow links below to get the details.

## Acknowledgement
+ Semtech LoRa http://www.semtech.com/wireless-rf/lora.html
+ IBM LoRaWAN IN C http://www.research.ibm.com/labs/zurich/ics/lrsc/lmic.html
+ LoRa Alliance https://www.lora-alliance.org/
+ kgabis. parson (JSON parser) https://github.com/kgabis/parson
+ Semtech LoRa Net lora_gateway https://github.com/lora-net/lora_gateway
+ Semtech LoRa Net packet_forwarder https://github.com/Lora-net/packet_forwarder
+ TTN poly_pkt_fwd https://github.com/TheThingsNetwork/packet_forwarder
+ Brian Gladman. AES library http://www.gladman.me.uk/
+ Lander Casado, Philippas Tsigas. CMAC library http://www.cse.chalmers.se/research/group/dcs/masters/contikisec/
+ diabloneo timespec_diff gitst https://gist.github.com/diabloneo/9619917
+ CCAN (json libary is from CCAN project) https://ccodearchive.net/