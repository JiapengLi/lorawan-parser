# Introduction

This LoRaWAN tool is for LoRaWAN developers who need know the details of LoRaWAN protocol.

With lorawan-parser, one could see all details of LoRaWAN, like how frames are defined, how data is encrypted and decrypted etc.

## Features

- [x] Support LoRaWAN 1.0 protocol
- [x] Support both ABP and OTAA mode device
- [x] Colorful terminal outputs (Windows MiniTTY not supported)
- [ ] Cross platform (Tested on Ubuntu, Lubuntu, Raspberry Pi, Windows)
- [ ] Support LoRaWAN 1.0.2 protocol
- [ ] Live parse LoRaWAN motes message (To support Semtech IoT Start Kit)

# Compile

## Linux

Depends on tools *libtool*, *automake*. To build:

    cd lorawan-parser
    autoreconf -i
    ./configure
    make

## Windows

### Codeblocks
lorawan-parser supports [Codeblocks](http://www.codeblocks.org/) project. One could download Codeblocks from its official website.

### CMake
*Not supported yet. You are welcome to submit CMake patches.*

## Raspberry Pi

    sudo apt-get install autoconf libtool
    autoreconf -i
    ./configure
    make

## Big Endian Platform (untested)

    autoreconf -i
    ./configure --enable-big-endian
    make

# Usage

Refer to `util/test/main.c` to know the usage of lorawan API.

After compile find `lwp.exe/lwp` under `util/parser/` directory to parse the LoRaWAN frame.

## Burst Parse LoRaWAN Frame
    # WIN
    lwp.exe -c lwp-config.json
    # Linux
    lwp -c lwp-config.json

To go further, user could fill their own LoRaWAN frames in a json file to parse it.

## Parse LoRaWAN MACCMD
    $ ./util/parser/lwp.exe -T CD -m "02 30 01"
    MACCMD: 02 30 01
    MACCMD ( LinkCheckAns )
    Margin: 48dB
    GwCnt: 1

## Limitation

lorawan-parser only handles frames of which real frame counter is less than 0xFFFF, this is because an exact LoRaWAN frame only record low 16bits of the frame, the parser alwarys assumes the high 16bits is zero.

### Frame counter enhancement
API is updated to receive frame counter 16 most-significante bits passed from user. This makes it possible to emunate the frame counter most significante bits when a frame is known to be valid

# Contribute

Any kind of contributions are welcome, issue report, pull requests,  WIKI, suggestions...

Before you send pull request, please try to make your code keep same style as the original one.

# License
lorawan-paser and is licensed under [The MIT License](http://opensource.org/licenses/mit-license.php). Check LICENSE.txt for more information.

parson, AES, CMAC have its own licenses. Please follow links below to get the details.

# Acknowledgement

+ Semtech LoRa http://www.semtech.com/wireless-rf/lora.html
+ LoRa Alliance https://www.lora-alliance.org/
+ kgabis. parson (JSON parser) https://github.com/kgabis/parson
+ Semtech LoRa Net lora_gateway https://github.com/lora-net/lora_gateway
+ Brian Gladman. AES library http://www.gladman.me.uk/
+ Lander Casado, Philippas Tsigas. CMAC library http://www.cse.chalmers.se/research/group/dcs/masters/contikisec/
