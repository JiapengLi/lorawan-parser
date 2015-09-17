# Introduction

This LoRaWAN tool is for LoRaWAN developers who need know the details of LoRaWAN protocol.

With lorawan-parser, one could see all details of LoRaWAN, like how frames are defined, how data is encrypted and decrypted etc.

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
*Not supported yet. You are welcome to send me CMake patches.*

# Usage

Refer to `util/test/main.c` to know the usage of lorawan API.

After compile find `lwp.exe/lwp` under `util/parser/` directory to parse the LoRaWAN frame.

    # WIN
    lwp.exe -c lwp-config.json
    # Linux
    lwp -c lwp-config.json

To go further, user could fill their own LoRaWAN frames in a json file to parse it.

# Contribute

Any kind of contributions are welcome, issue report, pull requests,  WIKI, suggestions...

Before you send pull request, please try to make your code keep same style as the original one.

# License
parson, AES, CMAC have its own licenses. Please follow links below to know the details.

*lorawan-paser has no license yet, to be defined.*

# Acknowledgement

+ [LoRa Alliance](https://www.lora-alliance.org/)
+ kgabis. parson (JSON parser) https://github.com/kgabis/parson
+ Brian Gladman. AES library http://www.gladman.me.uk/
+ Lander Casado, Philippas Tsigas. CMAC library http://www.cse.chalmers.se/research/group/dcs/masters/contikisec/
