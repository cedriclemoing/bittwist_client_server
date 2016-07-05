# bittwist_client_server
modified version of bittwist to replay a pcap file on a client and a server for traffic simulation on routers

The goal is to test a wifi router under load, using multiples clients playing a pcap file as it was real users.
SERVER <-> DEVICE UNDER TEST (DUT) <-> CLIENT

The server and client are playing quite the same pcap files, with some adjustments on mac/IP adresses or IP TTL.
 
steps to use it:
1. generate a capture file on the server or device under test, by making some traffic on the client (on some routers, tcpdump does not give accurate timestamps, so prefer the capture on the server)
2. modify the pcap file: you may have to change source/dest mac adress and ip adress, and also IP TTL field (when a packet passes a router, its TTL field is decreased)
3. on the server side, run: bittwist -i interface -w dut_mac_adress -x server_file.pcap
4. on the client side, run: bittwist -i interface -w client_mac_adress client_file.pcap

note:
If you test it on a network connected to internet, you'll have a lot of RESET packets coming from the real servers to which the packets are sent (because sequence numbers will differ from the ones we have in the capture).
If your DUT is a router, perhaps you'll be able only to test a tcp only capture (arp/dhcp packets may be processed differently by the router).


