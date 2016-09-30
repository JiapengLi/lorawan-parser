# Packet Forwarder

- [ ] Try to find global_conf.json and local_conf.json under program folder
- [x] TX power and RX RSSI calibration file (lwp-cal-xxx.json xxx is gateway part number)
- [ ] Reuse packet_forwarder global_conf.json and local_conf.json configuration files
- [ ] Refer poly_pkt_fwd configuration
- [ ] Detect RF chip reset (https://github.com/TheThingsNetwork/packet_forwarder/pull/2)
- [ ] Auto detect RF front end (SX1255/SX1257)
- [ ] gateway_conf add packet_forwarder v1/v2 option
- [ ] percentage of each channel of the total 10 channels
- [ ] Packet lost ananlyze

## Possible
- [ ] https://github.com/brocaar/loraserver mqtt protocol
- [ ] support both IPV4 and IPV6 address

## Log level control

# Common
- [ ] ~~Replace parson with CCAN json library~~ (CCAN json doesn't support JSON data with comments)
- [ ] Add support to parse JoinAccept message
